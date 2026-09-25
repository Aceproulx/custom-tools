#!/usr/bin/env bash
# Enumerate Mitchat People Nearby rows from raw accessibility snapshots and
# optionally send a short greeting to each row through the Say Hi flow.
#
# Safety: the default mode is dry-run. Use --execute to send messages.
# The script keeps successful names in STATE_FILE so reruns do not resend.

set -uo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
AD_BIN="${AGENT_DEVICE_BIN:-agent-device}"
SESSION="${AGENT_DEVICE_SESSION:-cwd:9bd7e06eb732281e:default}"
MESSAGE="hi"
MODE="dry-run"
MAX_PASSES="${MAX_PASSES:-80}"
SCROLL_PIXELS="${SCROLL_PIXELS:-900}"
STATE_FILE="${STATE_FILE:-$SCRIPT_DIR/.sent_hi_names}"
LOG_FILE="${LOG_FILE:-$SCRIPT_DIR/.sent_hi.log}"

declare -a SKIP_NAMES=()
declare -A processed=()
declare -A skipped=()

usage() {
  cat <<'EOF'
Usage: send_hi_all.sh [options]

Options:
  --execute              Send the greeting (default is dry-run).
  --dry-run              Enumerate and print targets without opening profiles.
  --session SESSION      agent-device session (default: cwd:9bd7e06eb732281e:default).
  --message TEXT         Greeting to type (default: hi).
  --skip NAME            Do not process NAME; may be repeated.
  --state-file PATH      Successful-name state file.
  --log-file PATH        Per-target log file.
  --max-passes N         Maximum scroll passes (default: 80).
  --scroll-pixels N      Scroll distance per pass (default: 900).
  -h, --help             Show this help.

Examples:
  ./send_hi_all.sh --dry-run
  ./send_hi_all.sh --execute --skip bubu
EOF
}

while (($#)); do
  case "$1" in
    --execute) MODE="execute"; shift ;;
    --dry-run) MODE="dry-run"; shift ;;
    --session) [[ $# -ge 2 ]] || { echo "--session needs a value" >&2; exit 2; }; SESSION="$2"; shift 2 ;;
    --message) [[ $# -ge 2 ]] || { echo "--message needs a value" >&2; exit 2; }; MESSAGE="$2"; shift 2 ;;
    --skip) [[ $# -ge 2 ]] || { echo "--skip needs a value" >&2; exit 2; }; SKIP_NAMES+=("$2"); shift 2 ;;
    --state-file) [[ $# -ge 2 ]] || { echo "--state-file needs a value" >&2; exit 2; }; STATE_FILE="$2"; shift 2 ;;
    --log-file) [[ $# -ge 2 ]] || { echo "--log-file needs a value" >&2; exit 2; }; LOG_FILE="$2"; shift 2 ;;
    --max-passes) [[ $# -ge 2 ]] || { echo "--max-passes needs a value" >&2; exit 2; }; MAX_PASSES="$2"; shift 2 ;;
    --scroll-pixels) [[ $# -ge 2 ]] || { echo "--scroll-pixels needs a value" >&2; exit 2; }; SCROLL_PIXELS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$MAX_PASSES" in (''|*[!0-9]*) echo "--max-passes must be a positive integer" >&2; exit 2 ;; esac
case "$SCROLL_PIXELS" in (''|*[!0-9]*) echo "--scroll-pixels must be a positive integer" >&2; exit 2 ;; esac
((MAX_PASSES > 0 && SCROLL_PIXELS > 0)) || { echo "passes and scroll distance must be > 0" >&2; exit 2; }

key_for() {
  # Case-insensitive key for duplicate detection; retain the original label
  # for logging and for selecting the row.
  local value="${1//$'\t'/ }"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value,,}"
}

mark_processed() { processed["$(key_for "$1")"]=1; }
is_processed() { [[ -n "${processed[$(key_for "$1")]+present}" ]]; }
mark_skipped() { skipped["$(key_for "$1")"]=1; }
is_skipped() { [[ -n "${skipped[$(key_for "$1")]+present}" ]]; }

for name in "${SKIP_NAMES[@]}"; do
  mark_skipped "$name"
done

if [[ -f "$STATE_FILE" ]]; then
  while IFS= read -r saved_name || [[ -n "$saved_name" ]]; do
    [[ -n "$saved_name" ]] && mark_skipped "$saved_name"
  done < "$STATE_FILE"
fi

run_ad() {
  "$AD_BIN" "$@" --session "$SESSION"
}

log_line() {
  printf '%s\n' "$1" | tee -a "$LOG_FILE" >&2
}

# Parse only raw JSON lines. The raw output intentionally includes a warning
# and a human-readable node count before the JSON records; ignore both.
snapshot_rows() {
  local raw
  raw="$("$AD_BIN" snapshot -i --raw --session "$SESSION" 2>/dev/null)" || return 1
  RAW_SNAPSHOT="$raw"
  python3 -c '
import json, re, sys

nodes = []
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        nodes.append(json.loads(line))
    except json.JSONDecodeError:
        continue

by_index = {n.get("index"): n for n in nodes}
rows = []
for node in nodes:
    ident = node.get("identifier", "")
    if not ident.endswith("/nick_name"):
        continue
    name = str(node.get("label") or node.get("value") or "")
    name = re.sub(r"[\t\r\n]+", " ", name).strip()
    if not name:
        continue

    current = node
    row = None
    while current:
        if current.get("identifier", "").endswith("/nb_item"):
            row = current
            break
        parent = current.get("parentIndex")
        current = by_index.get(parent) if parent is not None else None
    if not row:
        continue

    rect = row.get("rect") or {}
    try:
        x = int(rect.get("x", 0)); y = int(rect.get("y", 0))
        w = int(rect.get("width", 0)); h = int(rect.get("height", 0))
    except (TypeError, ValueError):
        continue
    # Avoid the toolbar and the clipped/advertising row at the bottom. A later
    # scroll pass will bring a clipped row fully into this range.
    if y < 170 or y + h > 1500:
        continue
    cx = x + w // 2
    cy = y + h // 2
    rows.append((name, cx, cy, y, y + h))

# Preserve the first occurrence of a visible name and its current position.
seen = set()
for name, cx, cy, top, bottom in rows:
    key = name.casefold()
    if key in seen:
        continue
    seen.add(key)
    print(f"{name}\t{cx}\t{cy}\t{top}\t{bottom}")
' <<<"$raw"
}

return_to_list() {
  local attempt
  for attempt in 1 2 3; do
    if run_ad is visible 'label="People Nearby"' >/dev/null 2>&1; then
      run_ad wait stable 500 10000 >/dev/null 2>&1 || true
      return 0
    fi
    run_ad back >/dev/null 2>&1 || true
    run_ad wait stable 500 10000 >/dev/null 2>&1 || true
  done
  return 1
}

send_one() {
  local name="$1" x="$2" y="$3"
  mark_processed "$name"
  log_line "START\t$name\t($x,$y)"

  if [[ "$MODE" == "dry-run" ]]; then
    printf 'DRY-RUN\t%s\t(%s,%s)\n' "$name" "$x" "$y"
    return 0
  fi

  if ! run_ad press "$x" "$y" --settle >/dev/null; then
    log_line "ERROR\t$name\trow press failed"
    return_to_list || true
    return 1
  fi
  if ! run_ad wait text 'Say Hi' 10000 >/dev/null 2>&1 || ! run_ad is visible 'label="Say Hi"' >/dev/null 2>&1; then
    log_line "ERROR\t$name\tprofile did not expose Say Hi"
    return_to_list || true
    return 1
  fi
  if ! run_ad press 'label="Say Hi"' --settle >/dev/null; then
    log_line "ERROR\t$name\tSay Hi press failed"
    return_to_list || true
    return 1
  fi
  if ! run_ad wait text 'Send' 10000 >/dev/null 2>&1 || ! run_ad is visible 'id="com.michatapp.im:id/request_information"' >/dev/null 2>&1; then
    log_line "ERROR\t$name\tgreeting field missing"
    return_to_list || true
    return 1
  fi
  if ! run_ad press 'id="com.michatapp.im:id/request_information"' --settle >/dev/null; then
    log_line "ERROR\t$name\tfield focus failed"
    return_to_list || true
    return 1
  fi
  if ! run_ad type "$MESSAGE" --delay-ms 80 >/dev/null; then
    log_line "ERROR\t$name\ttyping failed"
    return_to_list || true
    return 1
  fi
  if ! run_ad press 'label="Send"' --settle >/dev/null; then
    log_line "ERROR\t$name\tSend press failed"
    return_to_list || true
    return 1
  fi

  # The normal flow returns to the profile after Send. If the list is already
  # visible, do not press Back; otherwise click Back exactly once, then verify
  # that the People Nearby list is ready for the next contact.
  run_ad wait stable 500 10000 >/dev/null 2>&1 || true
  if ! run_ad is visible 'label="People Nearby"' >/dev/null 2>&1; then
    if ! run_ad back >/dev/null 2>&1; then
      log_line "ERROR\t$name\tBack after Send failed"
      return 1
    fi
  fi
  if ! run_ad wait text 'People Nearby' 10000 >/dev/null 2>&1; then
    log_line "ERROR\t$name\tPeople Nearby did not return after Back"
    return 1
  fi

  printf 'SENT\t%s\n' "$name"
  printf '%s\n' "$name" >> "$STATE_FILE"
  return 0
}

# Start at the top so the traversal is repeatable.
if ! run_ad is visible 'label="People Nearby"' >/dev/null 2>&1; then
  echo "The active screen is not People Nearby; start Mitchat there first." >&2
  exit 1
fi
run_ad scroll top >/dev/null 2>&1 || true
run_ad wait stable 500 10000 >/dev/null 2>&1 || true

previous_rows=""
stagnant=0
failures=0

for ((pass=1; pass<=MAX_PASSES; pass++)); do
  rows="$(snapshot_rows)" || {
    failures=$((failures + 1))
    if ((failures >= 5)); then
      echo "Unable to read raw People Nearby snapshots after 5 attempts." >&2
      exit 1
    fi
    run_ad wait stable 500 10000 >/dev/null 2>&1 || true
    continue
  }
  failures=0

  candidate=""
  while IFS=$'\t' read -r name x y top bottom; do
    [[ -n "$name" ]] || continue
    key="$(key_for "$name")"
    [[ -n "$key" ]] || continue
    if is_skipped "$name" || is_processed "$name"; then
      continue
    fi
    if ! [[ "$x" =~ ^-?[0-9]+$ && "$y" =~ ^-?[0-9]+$ ]]; then
      continue
    fi
    candidate="$name"$'\t'"$x"$'\t'"$y"
    break
  done <<< "$rows"

  if [[ -n "$candidate" ]]; then
    stagnant=0
    IFS=$'\t' read -r name x y <<< "$candidate"
    send_one "$name" "$x" "$y" || true
    continue
  fi

  # No unseen fully visible row remains. Scroll until the viewport changes.
  if [[ "$rows" == "$previous_rows" ]]; then
    stagnant=$((stagnant + 1))
  else
    stagnant=0
  fi
  previous_rows="$rows"
  if ((stagnant >= 2)); then
    printf 'DONE\tno additional fully visible rows found after %d passes\n' "$pass" | tee -a "$LOG_FILE"
    break
  fi

  run_ad scroll down --pixels "$SCROLL_PIXELS" >/dev/null 2>&1 || true
  run_ad wait stable 500 10000 >/dev/null 2>&1 || true
done

if [[ "$MODE" == "dry-run" ]]; then
  printf 'DRY-RUN COMPLETE\tstate file unchanged: %s\n' "$STATE_FILE"
else
  printf 'RUN COMPLETE\tsession: %s\tstate: %s\n' "$SESSION" "$STATE_FILE"
fi
