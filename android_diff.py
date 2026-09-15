#!/usr/bin/env python3
"""
android_diff.py — Diff two Android APKs for bug bounty / mobile recon purposes.

Compares the raw contents of both APKs (extracted directly from the zip, so
the diff is deterministic and reflects exactly what shipped), and separately
decodes AndroidManifest.xml via jadx (resources-only, no Java source
decompilation) to diff manifest components.

Compares:
  1. File trees        -> files added / removed / changed (by hash), from the
                           raw APK zip contents.
  2. AndroidManifest.xml -> components added / removed / changed
     (activities, activity-aliases, services, receivers, providers,
      permissions, uses-permission, uses-feature)

Output (written to <output>/ , default "diff-output"):
  diff-output/
    files_added.txt
    files_removed.txt
    files_changed.txt
    manifest_diff.json
    report.html
    jadx_old.log / jadx_new.log   (full jadx output, for debugging)
    _extracted/old/, _extracted/new/   (raw APK zip contents, used for file diff)
    _resources/old/, _resources/new/   (jadx resources-only output, used for manifest)

Usage:
    python3 android_diff.py old_app.apk new_app.apk -o diff-output

Requires `jadx` on PATH (https://github.com/skylot/jadx) for manifest
decoding. If jadx fails on a packed/obfuscated manifest, a built-in
pure-Python binary-AXML decoder is used as fallback. You can also pass
already-decompiled directories instead of .apk files with --no-decompile
(skips jadx entirely, uses the dirs for both file and manifest diffing).
"""

import argparse
import difflib
import hashlib
import html
import json
import os
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import quote as url_quote

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)


def aname(tag):
    return f"{{{ANDROID_NS}}}{tag}"


# ---------------------------------------------------------------------------
# Binary AXML decoding fallback (pure Python, no external tools)
#
# Some packed/obfuscated APKs contain manifests that jadx and aapt both fail
# to parse (e.g. jadx writes 'Error decode manifest ...' into the output file,
# apkanalyzer dies with IndexOutOfBounds). The binary format itself is usually
# still walkable, so we decode it ourselves.
# ---------------------------------------------------------------------------

def _axml_escape(v):
    return (v.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _axml_string_pool(data, off):
    """Parse one RES_STRING_POOL_TYPE chunk -> list of strings."""
    hsz = struct.unpack_from("<H", data, off + 2)[0]
    sc = struct.unpack_from("<I", data, off + 8)[0]
    flags = struct.unpack_from("<I", data, off + 16)[0]
    sstart = struct.unpack_from("<I", data, off + 20)[0]
    utf8 = bool(flags & 0x100)
    strings = []
    base = off + sstart
    offs = struct.unpack_from(f"<{sc}I", data, off + hsz)
    for so in offs:
        p = base + so
        s = ""
        try:
            if utf8:
                n = data[p]; p += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[p]; p += 1
                l = data[p]; p += 1
                if l & 0x80:
                    l = ((l & 0x7F) << 8) | data[p]; p += 1
                s = data[p:p + l].decode("utf-8", "replace")
            else:
                n = struct.unpack_from("<H", data, p)[0]; p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                    p += 2
                s = data[p:p + n * 2].decode("utf-16-le", "replace")
        except Exception:
            pass
        strings.append(s)
    return strings


def _fmt_typed_value(strings, dt, dv):
    """Render a Res_value (dataType, data) as a string for attribute values."""
    if dv == 0xFFFFFFFF and dt == 0x00:
        return "@null"
    if dt == 0x03:   # STRING
        v = strings[dv] if 0 <= dv < len(strings) else None
        return _axml_escape(v) if v is not None else "?"
    if dt == 0x10:   # INT_DEC
        return str(struct.unpack("<i", struct.pack("<I", dv))[0])
    if dt == 0x11:   # INT_HEX
        return f"0x{dv:X}"
    if dt == 0x12:   # BOOLEAN
        return "true" if dv else "false"
    if dt == 0x01:   # REFERENCE (@res)
        return f"@{dv:08X}"
    if dt == 0x04:   # FLOAT
        try:
            return str(struct.unpack("<f", struct.pack("<I", dv))[0])
        except Exception:
            return str(dv)
    if dt == 0x02:   # ATTRIBUTE_REF — rare in manifests; render numerically
        return f"?{dv:08X}"
    return str(dv)


def decode_axml_bytes(data):
    """Decode raw binary Android AXMML bytes into an XML string."""
    t, hsz, total = struct.unpack_from("<HHI", data, 0)
    if t != 0x0003 or total > len(data):
        raise ValueError("not a valid AXML document")

    # Pass 1: locate the string pool.
    strings = None
    o = hsz
    while o + 8 <= min(total, len(data)):
        ct, chs, csz = struct.unpack_from("<HHI", data, o)
        if csz < 8 or o + csz > len(data):
            break
        if ct == 0x0001 and strings is None:
            strings = _axml_string_pool(data, o)
        o += csz
    if strings is None:
        raise ValueError("no string pool found")

    def s(i):
        return strings[i] if i is not None and 0 <= i < len(strings) else None

    out = []
    ns_stack = []       # resolved (prefix, uri) pairs currently open
    pending_ns = []     # namespaces declared before the next element

    o = hsz
    while o + 8 <= min(total, len(data)):
        ct, chs, csz = struct.unpack_from("<HHI", data, o)
        if csz < 8 or o + csz > len(data):
            break

        if ct == 0x0100:  # RES_XML_START_NAMESPACE_TYPE
            pfx_i, uri_i = struct.unpack_from("<ii", data, o + 16)
            ns_stack.append((s(pfx_i), s(uri_i)))
            pending_ns.append((s(pfx_i), s(uri_i)))

        elif ct == 0x0101:  # RES_XML_END_NAMESPACE_TYPE
            if ns_stack:
                ns_stack.pop()

        elif ct == 0x0102:  # RES_XML_START_ELEMENT_TYPE
            ename = s(struct.unpack_from("<i", data, o + 20)[0]) or "?"
            astart, asize, acount = struct.unpack_from("<HHH", data, o + 24)
            decl = ""
            for pfx, uri in pending_ns:
                if pfx and uri:
                    decl += f' xmlns:{pfx}="{_axml_escape(uri)}"'
            pending_ns.clear()
            out.append(f"<{ename}{decl}")
            base = o + 16 + astart  # attributeStart is relative to attrExt
            for i in range(acount):
                ao = base + i * max(asize, 20)
                if ao + 20 > len(data):
                    break
                ans_i, anm_i, araw_i = struct.unpack_from("<iii", data, ao)
                dt = data[ao + 15]
                dv = struct.unpack_from("<I", data, ao + 16)[0]
                nm = s(anm_i) or "?"
                uri = s(ans_i) if ans_i != -1 else None
                if uri:
                    for pfx, u in reversed(ns_stack):
                        if u == uri:
                            nm = f"{pfx}:{nm}" if pfx else nm
                            break
                raw = s(araw_i) if araw_i != -1 else None
                val = _axml_escape(raw) if raw is not None else _fmt_typed_value(strings, dt, dv)
                out.append(f' {nm}="{val}"')
            out.append(">")

        elif ct == 0x0103:  # RES_XML_END_ELEMENT_TYPE
            ename = s(struct.unpack_from("<i", data, o + 20)[0]) or "?"
            out.append(f"</{ename}>")

        elif ct == 0x0104:  # RES_XML_TEXT_TYPE
            txt_i = struct.unpack_from("<i", data, o + 16)[0]
            txt = s(txt_i)
            if txt and txt.strip():
                out.append(_axml_escape(txt.strip()))

        elif ct == 0x0105:  # RES_XML_CDATA_TYPE — treat like text
            txt_i = struct.unpack_from("<i", data, o + 16)[0]
            txt = s(txt_i)
            if txt:
                out.append(f"<![CDATA[{txt}]]>")

        elif ct == 0x0001:  # already-consumed string pool chunk
            pass

        o += csz

    xml = "".join(out)
    import xml.etree.ElementTree as _ET
    _ET.fromstring(xml)  # sanity check: we must produce well-formed XML
    return xml


def extract_and_decode_manifest(apk_path):
    """Pull AndroidManifest.xml straight from the APK zip and decode it with
    the built-in tolerant parser. Returns XML text; raises on failure."""
    import zipfile
    with zipfile.ZipFile(apk_path, "r") as zf:
        data = zf.read("AndroidManifest.xml")
    return decode_axml_bytes(data)


def manifest_is_parseable(path):
    """True if path exists and parses as XML (guards against jadx writing its
    error message into the output file instead of real XML)."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return False
    try:
        ET.parse(path)
        return True
    except ET.ParseError:
        return False


# ---------------------------------------------------------------------------
# APK decompilation (jadx)
# ---------------------------------------------------------------------------

def find_jadx(explicit_path=None):
    if explicit_path:
        if shutil.which(explicit_path) or os.path.isfile(explicit_path):
            return explicit_path
        print(f"[!] jadx not found at explicit path: {explicit_path}", file=sys.stderr)
        sys.exit(1)
    found = shutil.which("jadx")
    if found:
        return found
    print(
        "[!] 'jadx' not found on PATH.\n"
        "    Install it from https://github.com/skylot/jadx (download the release zip,\n"
        "    or `brew install jadx` / your package manager), then either add it to PATH\n"
        "    or pass --jadx-path /path/to/jadx.\n"
        "    Alternatively, pre-decompile both APKs yourself and pass those directories\n"
        "    with --no-decompile.",
        file=sys.stderr,
    )
    sys.exit(1)


def decompile_apk(jadx_bin, apk_path, out_dir, deobf=False, threads=4, log_path=None):
    """Run jadx on apk_path in resources-only mode (no Java source decompilation,
    we only need AndroidManifest.xml / res / assets decoded). Much faster and
    avoids the non-deterministic synthetic-class naming that full source
    decompilation introduces between separate runs. Returns out_dir."""
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    cmd = [jadx_bin, "-s", "-d", out_dir, "-j", str(threads)]
    if deobf:
        cmd.append("--deobf")
    cmd.append(apk_path)

    print(f"[*] Decoding resources/manifest for {apk_path} with jadx ...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if log_path:
        with open(log_path, "w") as f:
            f.write("CMD: " + " ".join(cmd) + "\n\n")
            f.write("--- stdout ---\n" + (result.stdout or "") + "\n")
            f.write("--- stderr ---\n" + (result.stderr or "") + "\n")

    manifest_path = os.path.join(out_dir, "resources", "AndroidManifest.xml")
    manifest_ok = manifest_is_parseable(manifest_path)

    if not manifest_ok and os.path.isfile(manifest_path) and os.path.getsize(manifest_path) > 0:
        # jadx "succeeded" but wrote an error message instead of XML
        # (happens on some packed/obfuscated APKs). Try our built-in decoder.
        print(f"[!] jadx produced a non-XML AndroidManifest.xml for {apk_path}; "
              f"trying built-in binary-AXML fallback decoder ...", file=sys.stderr)
        try:
            xml_str = extract_and_decode_manifest(apk_path)
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(xml_str)
            manifest_ok = True
            print(f"[+] Built-in fallback decoded the manifest successfully.", file=sys.stderr)
        except Exception as e:
            print(f"[!] Built-in AXML fallback failed for {apk_path}: {e}", file=sys.stderr)

    if result.returncode != 0 or not manifest_ok:
        tail = "\n".join((result.stderr or "").strip().splitlines()[-15:])
        if not manifest_ok:
            print(f"[!] jadx did not produce a usable AndroidManifest.xml for {apk_path}.", file=sys.stderr)
        else:
            print(f"[!] jadx reported warnings on {apk_path} (continuing with partial output).", file=sys.stderr)
        if tail:
            print(f"    Last jadx output:\n    " + tail.replace("\n", "\n    "), file=sys.stderr)
        if log_path:
            print(f"    Full log saved to: {log_path}", file=sys.stderr)
        if not manifest_ok and not (os.path.isdir(out_dir) and os.listdir(out_dir)):
            sys.exit(1)

    return out_dir


def extract_apk_zip(apk_path, out_dir):
    """Extract the raw APK (it's a zip) verbatim -- this is what we diff for the
    file-tree comparison. Deterministic, unlike decompiled Java source, so
    the diff reflects real content changes rather than decompiler artifacts."""
    import zipfile
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(out_dir)
    except zipfile.BadZipFile:
        print(f"[!] {apk_path} is not a valid APK/zip file.", file=sys.stderr)
        sys.exit(1)
    return out_dir


def decode_binary_xmls_in_tree(root_dir):
    """Compiled resources inside an APK (res/*.xml etc.) are binary AXML —
    unreadable in browsers/editors and useless for content diffs. Decode them
    IN PLACE with the built-in parser (files that aren't AXML are left alone).
    Returns (ok_count, fail_count)."""
    n_ok = n_fail = 0
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fn in filenames:
            if not fn.lower().endswith(".xml"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as f:
                    data = f.read(4)
                if len(data) < 4 or data[0] != 0x03 or data[1] != 0x00:
                    continue  # already plain-text XML or not AXML
                with open(p, "rb") as f:
                    xml_str = decode_axml_bytes(f.read())
                with open(p, "w", encoding="utf-8") as f:
                    f.write(xml_str)
                n_ok += 1
            except Exception:
                n_fail += 1
    return n_ok, n_fail


# ---------------------------------------------------------------------------
# File tree diffing
# ---------------------------------------------------------------------------

def hash_file(path, block_size=65536):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(block_size), b""):
                h.update(block)
        return h.hexdigest()
    except (IOError, OSError):
        return None


def walk_files(root):
    """Return dict of relative_path -> absolute_path for every file under root."""
    result = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            abs_path = os.path.join(dirpath, fn)
            rel_path = os.path.relpath(abs_path, root).replace(os.sep, "/")
            result[rel_path] = abs_path
    return result


def diff_files(old_dir, new_dir):
    old_files = walk_files(old_dir)
    new_files = walk_files(new_dir)

    old_set = set(old_files)
    new_set = set(new_files)

    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    common = sorted(old_set & new_set)

    changed = []
    for rel in common:
        oh = hash_file(old_files[rel])
        nh = hash_file(new_files[rel])
        if oh != nh:
            changed.append(rel)

    return {
        "added": added,
        "removed": removed,
        "changed": sorted(changed),
        "total_old": len(old_set),
        "total_new": len(new_set),
    }


# ---------------------------------------------------------------------------
# Manifest diffing
# ---------------------------------------------------------------------------

COMPONENT_TAGS = ["activity", "activity-alias", "service", "receiver", "provider"]
SIMPLE_LIST_TAGS = ["uses-permission", "uses-permission-sdk-23", "permission", "uses-feature"]


def find_manifest(root_dir):
    # jadx resources-only output location
    jadx_loc = os.path.join(root_dir, "resources", "AndroidManifest.xml")
    if os.path.isfile(jadx_loc) and os.path.getsize(jadx_loc) > 0:
        return jadx_loc
    # Standard apktool location
    direct = os.path.join(root_dir, "AndroidManifest.xml")
    if os.path.isfile(direct) and os.path.getsize(direct) > 0:
        return direct
    # Fallback: search
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        if "AndroidManifest.xml" in filenames:
            p = os.path.join(dirpath, "AndroidManifest.xml")
            if os.path.getsize(p) > 0:
                return p
    return None


def parse_intent_filters(elem):
    filters = []
    for intf in elem.findall("intent-filter"):
        actions = [a.get(aname("name")) for a in intf.findall("action")]
        categories = [c.get(aname("name")) for c in intf.findall("category")]
        data = []
        for d in intf.findall("data"):
            attrs = {k.split("}")[-1]: v for k, v in d.attrib.items()}
            if attrs:
                data.append(attrs)
        filters.append({
            "actions": [a for a in actions if a],
            "categories": [c for c in categories if c],
            "data": data,
        })
    return filters


def normalize_component_name(name, package):
    """Android allows android:name to be given relative to the package
    (leading '.', or a bare class name with no dots at all). Different build
    tools / jadx runs are inconsistent about resolving this to a fully
    qualified name, which would otherwise show up as spurious added+removed
    pairs in the diff. Normalize everything to fully-qualified form."""
    if not name or not package:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def parse_manifest(path):
    """Returns dict: {tag: {name: attrs_dict}} plus package/version info."""
    result = {tag: {} for tag in COMPONENT_TAGS}
    for tag in SIMPLE_LIST_TAGS:
        result[tag] = {}
    meta = {}

    if not path:
        return result, meta

    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"[!] Failed to parse manifest {path}: {e}", file=sys.stderr)
        return result, meta

    root = tree.getroot()
    meta["package"] = root.get("package")
    meta["versionCode"] = root.get(aname("versionCode"))
    meta["versionName"] = root.get(aname("versionName"))
    package = meta["package"]

    app = root.find("application")

    for tag in SIMPLE_LIST_TAGS:
        for elem in root.findall(tag):
            name = elem.get(aname("name"))
            if not name:
                continue
            attrs = {k.split("}")[-1]: v for k, v in elem.attrib.items()}
            result[tag][name] = attrs

    if app is not None:
        # application-level exported flag / attrs
        meta["application_attrs"] = {k.split("}")[-1]: v for k, v in app.attrib.items()}
        for tag in COMPONENT_TAGS:
            for elem in app.findall(tag):
                raw_name = elem.get(aname("name"))
                if not raw_name:
                    continue
                name = normalize_component_name(raw_name, package)
                attrs = {k.split("}")[-1]: v for k, v in elem.attrib.items()}
                attrs["_intent_filters"] = parse_intent_filters(elem)
                result[tag][name] = attrs

    return result, meta


def diff_component_dict(old_d, new_d):
    old_keys = set(old_d)
    new_keys = set(new_d)
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = {}
    for k in sorted(old_keys & new_keys):
        if old_d[k] != new_d[k]:
            changed[k] = {"old": old_d[k], "new": new_d[k]}
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        # full attribute dicts so the descriptive analysis can talk about
        # exported flags / intent filters of added & removed components
        "new_entries": {k: new_d[k] for k in added},
        "old_entries": {k: old_d[k] for k in removed},
    }


def diff_manifests(old_path, new_path):
    old_parsed, old_meta = parse_manifest(old_path)
    new_parsed, new_meta = parse_manifest(new_path)

    diff = {"meta": {"old": old_meta, "new": new_meta}, "components": {}}

    for tag in COMPONENT_TAGS + SIMPLE_LIST_TAGS:
        diff["components"][tag] = diff_component_dict(old_parsed.get(tag, {}), new_parsed.get(tag, {}))

    return diff


# ---------------------------------------------------------------------------
# Descriptive sentence generation
# ---------------------------------------------------------------------------

FRIENDLY_NAME = {
    "activity": "Activity",
    "activity-alias": "Activity alias",
    "service": "Service",
    "receiver": "Broadcast receiver",
    "provider": "Content provider",
    "uses-permission": "Permission (requested)",
    "uses-permission-sdk-23": "Permission (SDK23+ requested)",
    "permission": "Custom permission (defined)",
    "uses-feature": "Required feature",
}


def short_name(full_name):
    """Shorten a fully-qualified class/permission name for readability."""
    if not full_name:
        return full_name
    return full_name.split(".")[-1] if "." in full_name else full_name


# ---------------------------------------------------------------------------
# Descriptive manifest analysis
# ---------------------------------------------------------------------------

# Android "dangerous"-level permissions worth calling out when newly requested.
DANGEROUS_PERMISSIONS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "CAMERA",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_CALL_LOG", "CALL_PHONE",
    "WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
    "BODY_SENSORS", "BODY_SENSORS_BACKGROUND", "ACTIVITY_RECOGNITION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
    "POST_NOTIFICATIONS", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN",
    "NEARBY_WIFI_DEVICES", "UWB_RANGING",
}

# Sensitive switches on <application> worth narrating.
APP_ATTR_LABELS = {
    "allowBackup": ("Backup (allowBackup)",
                    "app private data can be extracted via adb backup"),
    "debuggable": ("Debuggable (debuggable)",
                   "the app can be attached to with a debugger"),
    "usesCleartextTraffic": ("Cleartext traffic (usesCleartextTraffic)",
                             "the app may send unencrypted HTTP traffic"),
    "networkSecurityConfig": ("Network security config", None),
    "requestLegacyExternalStorage": ("Legacy external storage", None),
}


def _boolish(v):
    return isinstance(v, str) and v.strip().lower() == "true"


def _version_labels(meta_old, meta_new):
    v1 = meta_old.get("versionName") or "v1"
    v2 = meta_new.get("versionName") or "v2"
    c1 = meta_old.get("versionCode")
    c2 = meta_new.get("versionCode")
    if c1:
        v1 = f"{v1} (code {c1})"
    if c2:
        v2 = f"{v2} (code {c2})"
    return v1, v2


def _intent_filters_summary(filters):
    """One-line human summary of what an intent-filter list handles."""
    parts = []
    acts = {a for f in filters for a in f.get("actions", [])}
    cats = {c for f in filters for c in f.get("categories", [])}
    schemes = {d.get("scheme") for f in filters for d in f.get("data", []) if d.get("scheme")}
    hosts = {d.get("host") for f in filters for d in f.get("data", []) if d.get("host")}
    if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
        parts.append("it is an app LAUNCHER entry point")
    short_actions = {
        "android.intent.action.VIEW": "VIEW",
        "android.intent.action.SEND": "SEND (share target)",
        "android.intent.action.SENDTO": "SENDTO",
        "android.intent.action.SENDMULTIPLE": "SEND_MULTIPLE",
    }
    named = [short_actions[a] for a in sorted(acts) if a in short_actions]
    custom = [a for a in sorted(acts) if a not in short_actions
              and a != "android.intent.action.MAIN"]
    if named:
        parts.append("handles intents: " + ", ".join(named))
    if custom:
        parts.append("custom actions: " + ", ".join(short_name(c) for c in custom[:4]))
    if schemes:
        parts.append("URL schemes: " + ", ".join(sorted(x for x in schemes if x)))
    if hosts:
        parts.append("hosts: " + ", ".join(sorted(x for x in hosts if x))[:120])
    return "; ".join(parts)


def _component_change_notes(old_attrs, new_attrs):
    """Human descriptions for attribute-level changes of one component."""
    notes = []  # (severity, text)

    oe, ne = old_attrs.get("exported"), new_attrs.get("exported")
    if oe != ne and ne is not None:
        if _boolish(ne):
            notes.append(("high",
                          f"is NOW EXPORTED (was {oe or 'unset'}) — other apps can "
                          f"invoke it directly"))
        elif ne.lower() == "false":
            notes.append(("info", "is no longer exported"))

    op, np_ = old_attrs.get("permission"), new_attrs.get("permission")
    if op != np_:
        if np_ and not op:
            notes.append(("info", f"now requires callers to hold permission "
                                  f"'{short_name(np_)}'"))
        elif op and not np_:
            notes.append(("info", f"no longer requires permission '{short_name(op)}'"))
        else:
            notes.append(("info", f"required permission changed: "
                                  f"'{short_name(op)}' -> '{short_name(np_)}'"))

    oen, nen = old_attrs.get("enabled"), new_attrs.get("enabled")
    if oen != nen and nen is not None:
        if nen.lower() == "false":
            notes.append(("info", "is DISABLED in this version"))
        elif nen.lower() == "true":
            notes.append(("info", "is now explicitly enabled"))

    ogp, ngp = old_attrs.get("grantUriPermissions"), new_attrs.get("grantUriPermissions")
    if ogp != ngp and ngp is not None and _boolish(ngp):
        notes.append(("high", "now grants URI permissions to other apps"))

    return notes


def _intent_filter_diff_notes(old_filters, new_filters):
    def collect(fl, key):
        vals = set()
        for f in fl:
            if key in ("schemes-hosts", "mimes"):
                for dd in f.get("data", []):
                    if key == "schemes-hosts":
                        if dd.get("scheme"):
                            vals.add(dd["scheme"])
                        if dd.get("host"):
                            vals.add(dd["host"])
                    else:
                        if dd.get("mimeType"):
                            vals.add(dd["mimeType"])
            else:
                vals.update(f.get(key, []))
        return vals

    oa, na_ = collect(old_filters, "actions"), collect(new_filters, "actions")
    oc, nc = collect(old_filters, "categories"), collect(new_filters, "categories")
    osd, nsd = collect(old_filters, "schemes-hosts"), collect(new_filters, "schemes-hosts")
    om, nm = collect(old_filters, "mimes"), collect(new_filters, "mimes")

    bits = []
    if na_ - oa:
        bits.append("gained intent actions: " + ", ".join(sorted(na_ - oa)[:5]))
    if oa - na_:
        bits.append("dropped intent actions: " + ", ".join(sorted(oa - na_)[:5]))
    if nc - oc:
        bits.append("gained categories: " + ", ".join(sorted(nc - oc)[:5]))
    if nsd - osd:
        bits.append("now handles URLs/data: " + ", ".join(sorted(nsd - osd)[:6]))
    if nm - om:
        bits.append("gains MIME types: " + ", ".join(sorted(nm - om)[:6]))
    if bits:
        return [("info", "its intent-filters changed — " + "; ".join(bits))]
    return []


def _resource_only_changes(old_attrs, new_attrs):
    """Left-over cosmetic attribute changes (labels/themes/icons)."""
    interesting_keys = {"label", "theme", "icon", "roundIcon"}
    bits = []
    for k in sorted((set(old_attrs) | set(new_attrs)) & interesting_keys):
        ov, nv = old_attrs.get(k), new_attrs.get(k)
        if ov != nv:
            ov_s = short_name(ov) if k not in ("theme",) else ov
            nv_s = short_name(nv) if k not in ("theme",) else nv
            bits.append(f"{k}: {ov_s} -> {nv_s}")
    return bits


def build_sentences(manifest_diff):
    """Produce rich, plain-language findings about manifest differences.

    Each sentence dict: {type: added|removed|changed|info,
                         severity: info|high,
                         tag, name, text}
    """
    meta = manifest_diff.get("meta", {})
    old_meta, new_meta = meta.get("old", {}), meta.get("new", {})
    v1, v2 = _version_labels(old_meta, new_meta)
    sentences = []

    # --- headline -------------------------------------------------------------
    pkg = old_meta.get("package") or new_meta.get("package")
    if pkg:
        sentences.append({
            "type": "info", "severity": "info", "tag": "headline", "name": pkg,
            "text": f"Package '{pkg}' upgraded from {v1} to {v2}."
        })

    # --- application-level switches --------------------------------------------
    oa = old_meta.get("application_attrs", {}) or {}
    na = new_meta.get("application_attrs", {}) or {}
    for key, (label, consequence) in APP_ATTR_LABELS.items():
        ov, nv = oa.get(key), na.get(key)
        if ov == nv:
            continue
        sev = "info"
        if key in ("debuggable", "allowBackup", "usesCleartextTraffic"):
            became_on = _boolish(nv) and not _boolish(ov)
            sev = "high" if became_on else "info"
        if consequence:
            text = (f"{label}: switched from '{ov or 'unset'}' to '{nv or 'unset'}' "
                    f"in {v2} — {consequence}.")
        else:
            text = f"{label} changed in {v2}: {ov or 'unset'} -> {nv or 'unset'}."
        sentences.append({"type": "changed", "severity": sev, "tag": "application",
                          "name": key, "text": text})

    # --- per-component-type sections ---------------------------------------------
    comps = manifest_diff.get("components", {})
    # uses-permission* are narrated in the dedicated permission section below
    for tag in COMPONENT_TAGS + SIMPLE_LIST_TAGS[2:]:
        d = comps.get(tag, {})
        label = FRIENDLY_NAME.get(tag, tag)
        if not (d.get("added") or d.get("removed") or d.get("changed")):
            continue

        for name in d.get("added", []):
            attrs_new = d.get("new_entries", {}).get(name, {})
            sev = "info"
            extra = ""
            if _boolish(attrs_new.get("exported")):
                sev = "high"
                extra += " It is EXPORTED — reachable by other apps."
            ifsum = _intent_filters_summary(attrs_new.get("_intent_filters") or [])
            if ifsum:
                extra += " " + ifsum[0].upper() + ifsum[1:] + "."
            sentences.append({
                "type": "added", "severity": sev, "tag": tag, "name": name,
                "text": f"{label} '{short_name(name)}' was ADDED in {v2}.{extra}"
            })

        for name in d.get("removed", []):
            attrs_old = d.get("old_entries", {}).get(name, {})
            note = ""
            if _boolish(attrs_old.get("exported")):
                note = " (it was EXPORTED — that attack surface is now gone)"
            sentences.append({
                "type": "removed", "severity": "info", "tag": tag, "name": name,
                "text": f"{label} '{short_name(name)}' was REMOVED in {v2} "
                        f"(present in {v1}){note}."
            })

        for name, delta in d.get("changed", {}).items():
            old_attrs, new_attrs = delta["old"], delta["new"]
            notes = _component_change_notes(old_attrs, new_attrs)
            notes += _intent_filter_diff_notes(
                old_attrs.get("_intent_filters") or [],
                new_attrs.get("_intent_filters") or [])

            if notes:
                worst = "high" if any(s == "high" for s, _ in notes) else "info"
                detail = "; ".join(t for _, t in notes)
                sentences.append({
                    "type": "changed", "severity": worst, "tag": tag, "name": name,
                    "text": f"{label} '{short_name(name)}' changed between {v1} "
                            f"and {v2}: {detail}."
                })
            else:
                bits = _resource_only_changes(old_attrs, new_attrs)
                if bits:
                    sentences.append({
                        "type": "changed", "severity": "info", "tag": tag,
                        "name": name,
                        "text": f"{label} '{short_name(name)}' updated resources in "
                                f"{v2} ({'; '.join(bits)})."
                    })
                else:
                    sentences.append({
                        "type": "changed", "severity": "info", "tag": tag,
                        "name": name,
                        "text": f"{label} '{short_name(name)}' declaration changed "
                                f"between {v1} and {v2}."
                    })

    # --- collapse add+remove pairs with identical class names into "moved" -----
    for tag in COMPONENT_TAGS:
        d = comps.get(tag, {})
        added, removed = d.get("added", []), d.get("removed", [])
        if not (added and removed):
            continue
        rem_by_short = {}
        for n in removed:
            rem_by_short.setdefault(short_name(n), []).append(n)
        moves, seen_removed = [], set()
        for an in added:
            sn = short_name(an)
            for rn in rem_by_short.get(sn, []):
                if rn != an and rn not in seen_removed:
                    moves.append((an, rn))
                    seen_removed.add(rn)
                    break
        if not moves:
            continue
        moved_added = {a for a, _ in moves}
        sentences = [s for s in sentences
                     if not (s.get("tag") == tag and (
                         (s["type"] == "added" and s.get("name") in moved_added) or
                         (s["type"] == "removed" and s.get("name") in seen_removed)))]
        for an, rn in moves:
            attrs_new = d.get("new_entries", {}).get(an, {})
            sev = "info"
            extra = ""
            if _boolish(attrs_new.get("exported")):
                sev = "high"
                extra = " It is EXPORTED in its new location."
            sentences.append({
                "type": "changed", "severity": sev, "tag": tag, "name": an,
                "text": f"{FRIENDLY_NAME.get(tag, tag)} '{short_name(an)}' was MOVED/"
                        f"REFACTORED between {v1} and {v2}: '{rn}' -> '{an}'.{extra}"
            })

    # --- permissions ---------------------------------------------------------------
    perm = comps.get("uses-permission", {})
    perm23 = comps.get("uses-permission-sdk-23", {})

    def emit_perms(container):
        for name in container:
            tail = (short_name(name) or "").split(".")[-1]
            dangerous = tail in DANGEROUS_PERMISSIONS
            if dangerous:
                text = (f"New DANGEROUS permission requested in {v2}: '{tail}' — "
                        f"gives access to sensitive user data or device capabilities.")
            else:
                text = f"New permission requested in {v2}: '{name}'."
            sentences.append({"type": "added", "severity": "high" if dangerous else "info",
                              "tag": "uses-permission", "name": name, "text": text})

    emit_perms(perm.get("added", []))
    emit_perms(perm23.get("added", []))
    for src in (perm, perm23):
        for name in src.get("removed", []):
            tail = (short_name(name) or "").split(".")[-1]
            note = " — sensitive access dropped" if tail in DANGEROUS_PERMISSIONS else ""
            sentences.append({
                "type": "removed", "severity": "info", "tag": "uses-permission",
                "name": name,
                "text": f"Permission '{short_name(name)}' is NO LONGER requested in "
                        f"{v2}{note}."
            })

    # security-relevant first, then added / removed / changed / info
    type_order = {"added": 0, "removed": 1, "changed": 2, "info": 3}
    sentences.sort(key=lambda s: (0 if s.get("severity") == "high" else 1,
                                  type_order.get(s["type"], 9)))
    return sentences


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Android Diff Report</title>
<style>
  :root {{
    --bg: #0f1117;
    --panel: #161923;
    --border: #262b3a;
    --text: #e6e8ee;
    --muted: #8b90a3;
    --added: #3fb950;
    --removed: #f85149;
    --changed: #d29922;
    --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0;
    padding: 0 0 60px 0;
  }}
  header {{
    padding: 32px 24px 20px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, #1a1f2e, #10131c);
  }}
  header h1 {{ margin: 0 0 6px; font-size: 1.6rem; }}
  header .sub {{ color: var(--muted); font-size: 0.9rem; }}
  .meta-row {{ display: flex; gap: 24px; margin-top: 14px; flex-wrap: wrap; }}
  .meta-box {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 16px; font-size: 0.85rem;
  }}
  .meta-box b {{ color: var(--accent); }}
  .summary {{
    display: flex; gap: 16px; padding: 24px; flex-wrap: wrap;
  }}
  .stat {{
    flex: 1; min-width: 140px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; text-align: center;
  }}
  .stat .num {{ font-size: 1.8rem; font-weight: 700; }}
  .stat .label {{ color: var(--muted); font-size: 0.8rem; margin-top: 4px; }}
  .stat.added .num {{ color: var(--added); }}
  .stat.removed .num {{ color: var(--removed); }}
  .stat.changed .num {{ color: var(--changed); }}
  main {{ padding: 0 24px; max-width: 980px; margin: 0 auto; }}
  section {{ margin-top: 32px; }}
  section h2 {{
    font-size: 1.15rem; border-bottom: 1px solid var(--border);
    padding-bottom: 8px; margin-bottom: 14px;
  }}
  .item {{
    display: flex; align-items: flex-start; gap: 10px;
    padding: 10px 12px; border-radius: 8px; margin-bottom: 6px;
    background: var(--panel); border: 1px solid var(--border);
    font-size: 0.92rem;
  }}
  .badge {{
    flex-shrink: 0; font-size: 0.7rem; font-weight: 700; text-transform: uppercase;
    padding: 3px 8px; border-radius: 20px; letter-spacing: 0.03em;
  }}
  .badge.added {{ background: rgba(63,185,80,0.15); color: var(--added); }}
  .badge.removed {{ background: rgba(248,81,73,0.15); color: var(--removed); }}
  .badge.changed {{ background: rgba(210,153,34,0.15); color: var(--changed); }}
  .badge.info {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
  .badge.attention {{
    background: rgba(248,81,73,0.25); color: #ff7b72;
    animation: none;
  }}
  .item.sevhigh {{
    border-color: rgba(248,81,73,0.45);
    background: linear-gradient(90deg, rgba(248,81,73,0.07), var(--panel) 40%);
  }}
  .fullname {{ color: var(--muted); font-size: 0.78rem; display: block; margin-top: 2px; word-break: break-all; }}
  .filelist {{ max-height: 480px; overflow-y: auto; }}
  .filelist .item {{ display: block; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; }}
  .filelist .item > .badge {{ display: inline-block; margin-bottom: 4px; }}
  .filerow {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .fname {{ word-break: break-all; }}
  .fsize {{ color: var(--muted); font-size: 0.76rem; flex-shrink: 0; }}
  .openlink {{
    color: var(--accent); text-decoration: none; font-size: 0.76rem;
    border: 1px solid var(--border); padding: 1px 8px; border-radius: 12px; flex-shrink: 0;
  }}
  .openlink:hover {{ background: rgba(88,166,255,0.12); }}
  .nolink {{ color: var(--muted); font-size: 0.76rem; font-style: italic; flex-shrink: 0; }}
  details.filecontent {{ width: 100%; margin-top: 6px; }}
  details.filecontent summary {{
    cursor: pointer; color: var(--muted); font-size: 0.76rem; user-select: none;
  }}
  details.filecontent summary:hover {{ color: var(--text); }}
  details.filecontent pre {{
    margin: 6px 0 0; padding: 10px; background: #0a0c12; border: 1px solid var(--border);
    border-radius: 6px; max-height: 320px; overflow: auto; font-size: 0.76rem; white-space: pre-wrap;
    word-break: break-all;
  }}
  pre.diffblock {{ white-space: pre; word-break: normal; }}
  .dl {{ display: block; }}
  .dl.add {{ background: rgba(63,185,80,0.12); color: var(--added); }}
  .dl.del {{ background: rgba(248,81,73,0.12); color: var(--removed); }}
  .dl.hunk {{ color: var(--accent); }}
  .empty {{ color: var(--muted); font-style: italic; padding: 8px 0; }}
  .manifest-scroll {{
    position: relative;
    overflow-y: auto;
    scrollbar-width: thin;
  }}
  .manifest-toggle {{
    color: var(--accent); text-decoration: none; font-size: .8rem;
    cursor: pointer; display: inline-block; margin-top: 10px;
  }}
  .manifest-toggle:hover {{ text-decoration: underline; }}
  /* ---- file viewer modal ---- */
  .modal-backdrop {{
    position: fixed; inset: 0; background: rgba(5,8,14,.72);
    display: none; z-index: 60;
  }}
  .modal-backdrop.open {{ display: block; }}
  .modal {{
    position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%);
    width: min(1100px, 93vw); height: 86vh;
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    display: flex; flex-direction: column; overflow: hidden;
    box-shadow: 0 18px 60px rgba(0,0,0,.55);
  }}
  .modal-head {{
    display: flex; align-items: center; gap: 10px;
    padding: 10px 16px; border-bottom: 1px solid var(--border);
  }}
  .modal-title {{
    font-size: .82rem; word-break: break-all;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }}
  .modal-close {{
    margin-left: auto; flex-shrink: 0;
    background: none; border: 1px solid var(--border); border-radius: 8px;
    color: var(--muted); font-size: 1rem; line-height: 1;
    width: 28px; height: 28px; cursor: pointer;
  }}
  .modal-close:hover {{ color: #fff; background: rgba(248,81,73,.2); }}
  .modal-body {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; }}
  .modal-toolbar {{
    display: flex; align-items: center; gap: 16px;
    padding: 8px 14px; border-bottom: 1px solid var(--border);
    font-size: .78rem; color: var(--muted);
  }}
  .dstat b.add {{ color: var(--added); }}
  .dstat b.del {{ color: var(--removed); }}
  .rawswitch {{ margin-left: auto; cursor: pointer; user-select: none; }}
  .rawswitch input {{ accent-color: var(--added); vertical-align: middle; margin-right: 5px; }}
  .fileframe {{ flex: 1; width: 100%; border: 0; background: #fff; }}
  .hidden {{ display: none !important; }}
  .modal-body pre.diffblock {{
    margin: 0; padding: 10px 14px; overflow: auto;
    background: #0a0c12; font-size: .78rem; height: 100%;
  }}
  .dl.ctx {{ opacity: .55; }}
</style>
</head>
<body>
<header>
  <h1>📱 Android Diff Report</h1>
  <div class="sub">Generated {generated_at}</div>
  <div class="meta-row">
    <div class="meta-box">Old package: <b>{old_pkg}</b> (v{old_vname} / {old_vcode})</div>
    <div class="meta-box">New package: <b>{new_pkg}</b> (v{new_vname} / {new_vcode})</div>
    <div class="meta-box">Files ≤ {inline_limit_label} get an inline preview/diff; files ≤ {link_limit_label} get an "open" link</div>
  </div>
</header>
<main>
  <div class="summary">
    <div class="stat added"><div class="num">{n_files_added}</div><div class="label">Files added</div></div>
    <div class="stat removed"><div class="num">{n_files_removed}</div><div class="label">Files removed</div></div>
    <div class="stat changed"><div class="num">{n_files_changed}</div><div class="label">Files changed</div></div>
    <div class="stat added"><div class="num">{n_manifest_added}</div><div class="label">Manifest entries added</div></div>
    <div class="stat removed"><div class="num">{n_manifest_removed}</div><div class="label">Manifest entries removed</div></div>
    <div class="stat changed"><div class="num">{n_manifest_changed}</div><div class="label">Manifest entries changed</div></div>
  </div>

  <section>
    <h2>Manifest analysis</h2>
    <div class="sub" style="color:var(--muted);font-size:.8rem;margin-bottom:10px;">
      Auto-generated plain-language summary of manifest differences. Items marked
      <span class="badge attention">security-relevant</span> affect the app's attack surface.
    </div>
    <div class="manifest-scroll" id="manifestScroll">
      {manifest_items_html}
    </div>
    <a href="#" class="manifest-toggle" id="manifestToggle"></a>
  </section>

  <section>
    <h2>String resources</h2>
    <div class="sub" style="color:var(--muted);font-size:.8rem;margin-bottom:10px;">
      res/values/strings.xml diff — {n_strings_added} added, {n_strings_removed} removed,
      {n_strings_changed} changed (locale variants not included).
    </div>
    <div class="filelist">{strings_html}</div>
  </section>

  <section>
    <h2>Files added</h2>
    <div class="filelist">{files_added_html}</div>
  </section>

  <section>
    <h2>Files removed</h2>
    <div class="filelist">{files_removed_html}</div>
  </section>

  <section>
    <h2>Files changed (same path, different content)</h2>
    <div class="filelist">{files_changed_html}</div>
  </section>
</main>
<div class="modal-backdrop" id="modalBackdrop">
  <div class="modal">
    <div class="modal-head">
      <span id="modalTitle" class="modal-title"></span>
      <button class="modal-close" id="modalClose" aria-label="Close">&#215;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>
<script src="report_data.js"></script>
<script>
(function() {{
  var list = document.getElementById('manifestScroll');
  var toggle = document.getElementById('manifestToggle');
  function collapse() {{
    if (!list) return;
    var items = list.querySelectorAll('.item');
    if (items.length <= 14) {{
      list.style.maxHeight = 'none';
      if (toggle) toggle.style.display = 'none';
      return;
    }}
    var top = items[0].offsetTop;
    var b = items[13];
    list.style.maxHeight = (b.offsetTop + b.offsetHeight + 6 - top) + 'px';
    if (toggle) toggle.textContent = 'Show all ' + items.length + ' findings';
  }}
  collapse();
  window.addEventListener('resize', function() {{
    if (list && list.style.maxHeight !== 'none') collapse();
  }});
  if (toggle) toggle.addEventListener('click', function(ev) {{
    ev.preventDefault();
    if (list.style.maxHeight === 'none') {{
      collapse();
    }} else {{
      list.style.maxHeight = 'none';
      toggle.textContent = 'Collapse manifest analysis';
    }}
  }});
}})();
</script>
<script>
(function() {{
  var D = window.REPORT_DIFFS || {{}};
  var backdrop = document.getElementById('modalBackdrop');
  var mtitle = document.getElementById('modalTitle');
  var mbody = document.getElementById('modalBody');
  function esc(s) {{
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }}
  function diffHtml(path) {{
    if (!Object.prototype.hasOwnProperty.call(D, path)) return null;
    var lines = D[path].split('\n');
    var out = ['<pre class="diffblock">'];
    for (var i = 0; i < lines.length; i++) {{
      var ln = lines[i];
      var t = ln.charAt(0);
      var cls = t === '+' ? 'add' : (t === '-' ? 'del' : (ln.indexOf('@@') === 0 ? 'hunk' : 'ctx'));
      var txt = esc(ln.indexOf('@@') === 0 ? ln : ln.substring(1));
      out.push('<span class="dl ' + cls + '">' + (txt.length ? txt : '&nbsp;') + '</span>');
    }}
    out.push('</pre>');
    return out.join('');
  }}
  function closeModal() {{
    backdrop.classList.remove('open');
    mbody.innerHTML = '';
  }}
  document.getElementById('modalClose').addEventListener('click', closeModal);
  backdrop.addEventListener('click', function(e) {{
    if (e.target === backdrop) closeModal();
  }});
  document.addEventListener('keydown', function(e) {{
    if (e.key === 'Escape') closeModal();
  }});
  document.addEventListener('click', function(ev) {{
    var a = ev.target.closest ? ev.target.closest('a.jsview') : null;
    if (!a) return;
    ev.preventDefault();
    var kind = a.getAttribute('data-kind') || 'file';
    var path = a.getAttribute('data-path') || '';
    var href = a.getAttribute('href');
    var chip = kind === 'new' ? '<span class="badge added">new</span> '
             : kind === 'old' ? '<span class="badge removed">old</span> ' : '';
    mtitle.innerHTML = chip + esc(path);
    var dv = diffHtml(path);
    if (kind === 'new' && dv !== null) {{
      var nAdd = 0, nDel = 0, ls = D[path].split('\n');
      for (var j = 0; j < ls.length; j++) {{
        var c = ls[j].charAt(0);
        if (c === '+') nAdd++; else if (c === '-') nDel++;
      }}
      mbody.innerHTML =
        '<div class="modal-toolbar">' +
        '<span class="dstat"><b class="add">+' + nAdd + '</b> added / ' +
        '<b class="del">-' + nDel + '</b> removed</span>' +
        '<label class="rawswitch"><input type="checkbox" id="rawChk">raw file</label></div>' +
        '<div id="diffWrap" style="flex:1;display:flex;flex-direction:column;overflow:hidden;">' +
        dv + '</div>' +
        '<iframe id="rawWrap" class="fileframe hidden" src="' + href + '"></iframe>';
      var chk = document.getElementById('rawChk');
      chk.addEventListener('change', function() {{
        var dw = document.getElementById('diffWrap');
        var rw = document.getElementById('rawWrap');
        if (chk.checked) {{ dw.classList.add('hidden'); rw.classList.remove('hidden'); }}
        else {{ rw.classList.add('hidden'); dw.classList.remove('hidden'); }}
      }});
    }} else {{
      mbody.innerHTML = '<iframe class="fileframe" src="' + href + '"></iframe>';
    }}
    backdrop.classList.add('open');
  }});
}})();
</script>
</body>
</html>
"""


def render_items_html(items_list_of_dicts):
    if not items_list_of_dicts:
        return '<div class="empty">No manifest changes found.</div>'
    rows = []
    for it in items_list_of_dicts:
        badge = it["type"]
        sev = it.get("severity", "info")
        sev_cls = " sevhigh" if sev == "high" else ""
        attention = ('<span class="badge attention" title="Security-relevant change">'
                     'security-relevant</span> ' if sev == "high" else "")
        rows.append(
            f'<div class="item{sev_cls}">{attention}'
            f'<span class="badge {badge}">{badge}</span>'
            f'<span>{html.escape(it["text"])}</span></div>'
        )
    return "\n".join(rows)


def human_size(n):
    if n is None:
        return "?"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def looks_like_text(path, sample_size=8192):
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    try:
        chunk.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def read_text_capped(path, max_bytes):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError:
        return None, False
    truncated = len(data) > max_bytes
    return data[:max_bytes].decode("utf-8", errors="replace"), truncated


def rel_href(out_dir, abs_path):
    """Relative URL from report.html (sitting in out_dir) to abs_path, URL-quoted."""
    rel = os.path.relpath(abs_path, out_dir).replace(os.sep, "/")
    return url_quote(rel, safe="/")


def render_added_removed_html(paths, badge, base_dir, out_dir, max_inline_bytes, max_link_bytes, keep_files=True):
    if not paths:
        return '<div class="empty">None found.</div>'
    rows = []
    for p in paths:
        abs_path = os.path.join(base_dir, p)
        try:
            size = os.path.getsize(abs_path)
        except OSError:
            size = None

        size_label = human_size(size)
        link_html = ""
        if keep_files and size is not None and size <= max_link_bytes:
            href = rel_href(out_dir, abs_path)
            link_html = (f'<a class="openlink jsview" href="{href}" '
                         f'data-path="{html.escape(p)}" data-kind="file" '
                         f'target="_blank" rel="noopener">open</a>')
        elif size is not None:
            link_html = '<span class="nolink">too large to open</span>' if keep_files else ""

        inline_html = ""
        if size is not None and size <= max_inline_bytes and looks_like_text(abs_path):
            text, truncated = read_text_capped(abs_path, max_inline_bytes)
            if text is not None:
                note = " (truncated)" if truncated else ""
                inline_html = (
                    f'<details class="filecontent"><summary>Preview{note}</summary>'
                    f'<pre>{html.escape(text)}</pre></details>'
                )

        rows.append(
            f'<div class="item"><span class="badge {badge}">{badge}</span>'
            f'<div class="filerow"><span class="fname">{html.escape(p)}</span>'
            f'<span class="fsize">{size_label}</span>{link_html}</div>{inline_html}</div>'
        )
    return "\n".join(rows)


def render_changed_html(paths, old_dir, new_dir, out_dir, max_inline_bytes, max_link_bytes, keep_files=True):
    if not paths:
        return '<div class="empty">None found.</div>'
    rows = []
    for p in paths:
        old_abs = os.path.join(old_dir, p)
        new_abs = os.path.join(new_dir, p)
        try:
            old_size = os.path.getsize(old_abs)
        except OSError:
            old_size = None
        try:
            new_size = os.path.getsize(new_abs)
        except OSError:
            new_size = None

        size_label = f"{human_size(old_size)} → {human_size(new_size)}"

        links = []
        if keep_files:
            for label, abs_path, size in (("old", old_abs, old_size), ("new", new_abs, new_size)):
                if size is not None and size <= max_link_bytes:
                    href = rel_href(out_dir, abs_path)
                    links.append(
                        f'<a class="openlink jsview" href="{href}" '
                        f'data-path="{html.escape(p)}" data-kind="{label}" '
                        f'target="_blank" rel="noopener">{label}</a>')
        links_html = "".join(links) if links else ('<span class="nolink">too large to open</span>' if keep_files else "")

        inline_html = ""
        can_diff = (
            old_size is not None and old_size <= max_inline_bytes and looks_like_text(old_abs)
            and new_size is not None and new_size <= max_inline_bytes and looks_like_text(new_abs)
        )
        if can_diff:
            old_text, _ = read_text_capped(old_abs, max_inline_bytes)
            new_text, _ = read_text_capped(new_abs, max_inline_bytes)
            if old_text is not None and new_text is not None:
                diff_lines = list(difflib.unified_diff(
                    old_text.splitlines(), new_text.splitlines(),
                    fromfile=f"old/{p}", tofile=f"new/{p}", lineterm=""
                ))[:2000]
                out_lines = []
                for line in diff_lines:
                    cls = "ctx"
                    if line.startswith("+++") or line.startswith("---"):
                        cls = "ctx"
                    elif line.startswith("+"):
                        cls = "add"
                    elif line.startswith("-"):
                        cls = "del"
                    elif line.startswith("@@"):
                        cls = "hunk"
                    out_lines.append(f'<span class="dl {cls}">{html.escape(line)}</span>')
                inline_html = (
                    '<details class="filecontent"><summary>View diff</summary>'
                    f'<pre class="diffblock">{"".join(out_lines)}</pre></details>'
                )
        elif old_size is not None and new_size is not None and (
            old_size > max_inline_bytes or new_size > max_inline_bytes
            or not looks_like_text(old_abs) or not looks_like_text(new_abs)
        ):
            inline_html = '<div class="nolink" style="padding:4px 0;">binary or too large to diff inline</div>'

        rows.append(
            f'<div class="item"><span class="badge changed">changed</span>'
            f'<div class="filerow"><span class="fname">{html.escape(p)}</span>'
            f'<span class="fsize">{size_label}</span>{links_html}</div>{inline_html}</div>'
        )
    return "\n".join(rows)


def build_embedded_diffs(file_diff, old_dir, new_dir,
                         per_file_cap=300 * 1024, total_cap=4 * 1024 * 1024):
    """Unified-diff blob per changed text file, consumed by the report's modal
    viewer (clicking 'new' highlights added lines in green)."""
    data = {}
    used = 0
    for p in file_diff["changed"]:
        o, n = os.path.join(old_dir, p), os.path.join(new_dir, p)
        try:
            so, sn = os.path.getsize(o), os.path.getsize(n)
        except OSError:
            continue
        if so > per_file_cap or sn > per_file_cap or not looks_like_text(o) or not looks_like_text(n):
            continue
        old_t = read_text_capped(o, per_file_cap)[0]
        new_t = read_text_capped(n, per_file_cap)[0]
        if old_t is None or new_t is None:
            continue
        dd = list(difflib.unified_diff(old_t.splitlines(), new_t.splitlines(), lineterm=""))[2:]
        blob = "\n".join(dd)
        if len(blob) > per_file_cap:
            continue  # absurdly diff-heavy file; raw view still available
        if used + len(blob) > total_cap:
            break
        used += len(blob)
        data[p] = blob
    return data


# ---------------------------------------------------------------------------
# String-resource diffing
# ---------------------------------------------------------------------------

def find_strings_xml(root_dir):
    for cand in (os.path.join(root_dir, "resources", "res", "values", "strings.xml"),
                 os.path.join(root_dir, "res", "values", "strings.xml")):
        if os.path.isfile(cand) and os.path.getsize(cand) > 0:
            return cand
    return None


def parse_strings_xml(path):
    """name -> value from a decoded strings.xml."""
    out = {}
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return out
    for el in tree.getroot():
        if el.tag == "string":
            name = el.get("name")
            if name:
                out[name] = "".join(el.itertext()).strip()
    return out


def diff_strings(old_map, new_map):
    added = sorted(set(new_map) - set(old_map))
    removed = sorted(set(old_map) - set(new_map))
    changed = [(n, old_map[n], new_map[n])
               for n in sorted(set(old_map) & set(new_map)) if old_map[n] != new_map[n]]
    return {"added": added, "removed": removed, "changed": changed,
            "added_values": {n: new_map[n] for n in added},
            "removed_values": {n: old_map[n] for n in removed}}


def render_strings_html(sdiff, max_value_chars=160):
    rows = []
    def clip(v):
        v = v or ""
        return v if len(v) <= max_value_chars else v[:max_value_chars] + "…"
    for n in sdiff["added"]:
        rows.append(f'<div class="item"><span class="badge added">added</span>'
                    f'<span><code>{html.escape(n)}</code> = '
                    f'"{html.escape(clip(sdiff["added_values"].get(n, "")))}"</span></div>')
    for n in sdiff["removed"]:
        rows.append(f'<div class="item"><span class="badge removed">removed</span>'
                    f'<span><code>{html.escape(n)}</code> = '
                    f'"{html.escape(clip(sdiff["removed_values"].get(n, "")))}"</span></div>')
    for n, ov, nv in sdiff["changed"]:
        rows.append(f'<div class="item"><span class="badge changed">changed</span>'
                    f'<span><code>{html.escape(n)}</code>: '
                    f'"{html.escape(clip(ov))}" → "{html.escape(clip(nv))}"</span></div>')
    if not rows:
        return '<div class="empty">No string changes found.</div>'
    return "\n".join(rows)


def build_html_report(file_diff, manifest_diff, sentences, old_dir, new_dir, out_dir,
                       max_inline_bytes, max_link_bytes, keep_files=True,
                       strings_diff=None):
    meta = manifest_diff.get("meta", {})
    old_meta, new_meta = meta.get("old", {}), meta.get("new", {})
    strings_diff = strings_diff or {"added": [], "removed": [], "changed": [],
                                    "added_values": {}, "removed_values": {}}

    n_added = sum(1 for s in sentences if s["type"] == "added")
    n_removed = sum(1 for s in sentences if s["type"] == "removed")
    n_changed = sum(1 for s in sentences if s["type"] == "changed")

    html_out = HTML_TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        old_pkg=html.escape(old_meta.get("package") or "unknown"),
        old_vname=html.escape(old_meta.get("versionName") or "?"),
        old_vcode=html.escape(old_meta.get("versionCode") or "?"),
        new_pkg=html.escape(new_meta.get("package") or "unknown"),
        new_vname=html.escape(new_meta.get("versionName") or "?"),
        new_vcode=html.escape(new_meta.get("versionCode") or "?"),
        inline_limit_label=human_size(max_inline_bytes),
        link_limit_label=human_size(max_link_bytes),
        n_files_added=len(file_diff["added"]),
        n_files_removed=len(file_diff["removed"]),
        n_files_changed=len(file_diff["changed"]),
        n_manifest_added=n_added,
        n_manifest_removed=n_removed,
        n_manifest_changed=n_changed,
        manifest_items_html=render_items_html(sentences),
        strings_html=render_strings_html(strings_diff),
        n_strings_added=len(strings_diff["added"]),
        n_strings_removed=len(strings_diff["removed"]),
        n_strings_changed=len(strings_diff["changed"]),
        files_added_html=render_added_removed_html(
            file_diff["added"], "added", new_dir, out_dir, max_inline_bytes, max_link_bytes, keep_files),
        files_removed_html=render_added_removed_html(
            file_diff["removed"], "removed", old_dir, out_dir, max_inline_bytes, max_link_bytes, keep_files),
        files_changed_html=render_changed_html(
            file_diff["changed"], old_dir, new_dir, out_dir, max_inline_bytes, max_link_bytes, keep_files),
    )
    return html_out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Diff two Android APKs (or pre-decompiled dirs) for bug bounty / mobile recon."
    )
    parser.add_argument("old_app", help="Path to the OLD .apk (or a decompiled directory with --no-decompile)")
    parser.add_argument("new_app", help="Path to the NEW .apk (or a decompiled directory with --no-decompile)")
    parser.add_argument("-o", "--output", default="diff-output", help="Output directory (default: diff-output)")
    parser.add_argument("--no-decompile", action="store_true",
                         help="Treat old_app/new_app as already-decompiled directories instead of .apk files")
    parser.add_argument("--jadx-path", default=None, help="Explicit path to the jadx binary")
    parser.add_argument("--deobf", action="store_true", help="Enable jadx deobfuscation")
    parser.add_argument("--threads", type=int, default=4, help="jadx decompile threads (default: 4)")
    parser.add_argument("--no-keep-decompiled", action="store_true",
                         help="Delete the extracted/decoded APK trees after diffing (kept by default under "
                              "<output>/_extracted/ and <output>/_resources/ for further manual recon)")
    parser.add_argument("--max-inline-size", type=int, default=300 * 1024,
                         help="Max file size in bytes to show an inline preview/diff in report.html "
                              "(default: 307200 = 300KB)")
    parser.add_argument("--max-link-size", type=int, default=5 * 1024 * 1024,
                         help="Max file size in bytes to add a clickable 'open' link in report.html "
                              "(default: 5242880 = 5MB)")
    args = parser.parse_args()

    out_dir = os.path.abspath(args.output)
    os.makedirs(out_dir, exist_ok=True)

    if args.no_decompile:
        # Directories already provided (apktool/jadx output) — use as-is for both
        # file-tree diffing and manifest lookup.
        old_dir = os.path.abspath(args.old_app)
        new_dir = os.path.abspath(args.new_app)
        if not os.path.isdir(old_dir):
            print(f"[!] Old dir not found: {old_dir}", file=sys.stderr)
            sys.exit(1)
        if not os.path.isdir(new_dir):
            print(f"[!] New dir not found: {new_dir}", file=sys.stderr)
            sys.exit(1)
        old_manifest_dir, new_manifest_dir = old_dir, new_dir
    else:
        old_apk = os.path.abspath(args.old_app)
        new_apk = os.path.abspath(args.new_app)
        if not os.path.isfile(old_apk):
            print(f"[!] Old APK not found: {old_apk}", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(new_apk):
            print(f"[!] New APK not found: {new_apk}", file=sys.stderr)
            sys.exit(1)

        # 1) Raw zip extraction -> used for the file-tree diff. Deterministic:
        #    exact bytes as packaged, no decompiler-introduced noise (renamed
        #    synthetic/lambda classes etc. that vary between jadx runs).
        extracted_root = os.path.join(out_dir, "_extracted")
        old_dir = extract_apk_zip(old_apk, os.path.join(extracted_root, "old"))
        new_dir = extract_apk_zip(new_apk, os.path.join(extracted_root, "new"))

        # 1b) Compiled resources are binary AXML; decode in place so report
        #     links/previews show readable XML and diffs compare real content.
        for label, d in (("old", old_dir), ("new", new_dir)):
            ok, bad = decode_binary_xmls_in_tree(d)
            if ok or bad:
                print(f"[*] Decoded {ok} binary XML resource file(s) from the {label} APK"
                      + (f" ({bad} failed, left as-is)" if bad else ""))

        # 2) jadx resources-only pass -> used only to decode the binary
        #    AndroidManifest.xml into readable XML. No Java source decompiled,
        #    so this is fast and its output isn't used for the file diff.
        jadx_bin = find_jadx(args.jadx_path)
        resources_root = os.path.join(out_dir, "_resources")
        old_manifest_dir = decompile_apk(
            jadx_bin, old_apk, os.path.join(resources_root, "old"),
            deobf=args.deobf, threads=args.threads,
            log_path=os.path.join(out_dir, "jadx_old.log"),
        )
        new_manifest_dir = decompile_apk(
            jadx_bin, new_apk, os.path.join(resources_root, "new"),
            deobf=args.deobf, threads=args.threads,
            log_path=os.path.join(out_dir, "jadx_new.log"),
        )

    print("[*] Diffing file trees...")
    file_diff = diff_files(old_dir, new_dir)

    print("[*] Locating and diffing AndroidManifest.xml...")
    old_manifest = find_manifest(old_manifest_dir)
    new_manifest = find_manifest(new_manifest_dir)
    if not old_manifest:
        print(f"[!] Warning: no usable AndroidManifest.xml found for the old APK "
              f"(check jadx_old.log in {out_dir})", file=sys.stderr)
    if not new_manifest:
        print(f"[!] Warning: no usable AndroidManifest.xml found for the new APK "
              f"(check jadx_new.log in {out_dir})", file=sys.stderr)

    manifest_diff = diff_manifests(old_manifest, new_manifest)
    sentences = build_sentences(manifest_diff)

    # String-resource diff (from jadx-decoded res/values/strings.xml)
    print("[*] Diffing string resources...")
    old_strings_xml = find_strings_xml(old_manifest_dir)
    new_strings_xml = find_strings_xml(new_manifest_dir)
    if not old_strings_xml or not new_strings_xml:
        print("[!] Could not locate decoded strings.xml for both versions; "
              "string diff skipped.", file=sys.stderr)
        strings_diff = {"added": [], "removed": [], "changed": [],
                        "added_values": {}, "removed_values": {}}
    else:
        strings_diff = diff_strings(parse_strings_xml(old_strings_xml),
                                    parse_strings_xml(new_strings_xml))
        print(f"[*] Strings: {len(strings_diff['added'])} added, "
              f"{len(strings_diff['removed'])} removed, "
              f"{len(strings_diff['changed'])} changed")

    # Write plain text file lists
    with open(os.path.join(out_dir, "files_added.txt"), "w") as f:
        f.write("\n".join(file_diff["added"]) + "\n")
    with open(os.path.join(out_dir, "files_removed.txt"), "w") as f:
        f.write("\n".join(file_diff["removed"]) + "\n")
    with open(os.path.join(out_dir, "files_changed.txt"), "w") as f:
        f.write("\n".join(file_diff["changed"]) + "\n")

    # Write manifest diff JSON
    with open(os.path.join(out_dir, "manifest_diff.json"), "w") as f:
        json.dump({"components": manifest_diff["components"], "meta": manifest_diff["meta"],
                   "sentences": sentences}, f, indent=2)

    # Write strings diff JSON
    with open(os.path.join(out_dir, "strings_diff.json"), "w") as f:
        json.dump(strings_diff, f, indent=2)

    # Pre-compute per-file diffs consumed by the report's popup viewer
    # (clicking "new" shows added lines highlighted in green).
    diffs = build_embedded_diffs(file_diff, old_dir, new_dir,
                                 per_file_cap=args.max_inline_size)
    with open(os.path.join(out_dir, "report_data.js"), "w") as f:
        f.write("window.REPORT_DIFFS = "
                + json.dumps(diffs, ensure_ascii=False).replace("</", "<\\/")
                + ";")
    print(f"[*] Embedded inline diffs for {len(diffs)} changed file(s) -> report_data.js")

    # Write HTML report
    report_html = build_html_report(
        file_diff, manifest_diff, sentences, old_dir, new_dir, out_dir,
        max_inline_bytes=args.max_inline_size, max_link_bytes=args.max_link_size,
        keep_files=(args.no_decompile or not args.no_keep_decompiled),
        strings_diff=strings_diff,
    )
    with open(os.path.join(out_dir, "report.html"), "w") as f:
        f.write(report_html)

    if not args.no_decompile and args.no_keep_decompiled:
        shutil.rmtree(os.path.join(out_dir, "_extracted"), ignore_errors=True)
        shutil.rmtree(os.path.join(out_dir, "_resources"), ignore_errors=True)

    print(f"[*] Done. Output written to: {out_dir}")
    print(f"    - {len(file_diff['added'])} files added, {len(file_diff['removed'])} removed, {len(file_diff['changed'])} changed")
    n_sec = sum(1 for s in sentences if s.get('severity') == 'high')
    print(f"    - Manifest: {sum(1 for s in sentences if s['type']=='added')} added, "
          f"{sum(1 for s in sentences if s['type']=='removed')} removed, "
          f"{sum(1 for s in sentences if s['type']=='changed')} changed "
          f"({n_sec} security-relevant)")
    print(f"    Open {os.path.join(out_dir, 'report.html')} in a browser to view the report.")


if __name__ == "__main__":
    main()
