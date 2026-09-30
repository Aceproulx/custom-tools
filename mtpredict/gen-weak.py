#!/usr/bin/env python3
"""
gen-weak - generate DELIBERATELY INSECURE random numbers, for testing mtpredict.

This script is a bad-example generator on purpose. Every weakness in it is
intentional and documented. Do not copy any of it into anything real.

    gen-weak.py                      1000 six-digit numbers to stdout
    gen-weak.py --count 5000         more of them
    gen-weak.py --out numbers.txt    write to a file
    gen-weak.py --leak leak.txt      also dump 624 getrandbits(32) values

What is wrong with it, and why (in rough order of how much each one matters):

  1. random.randint(100000, 999999) for "random" numbers
     Only 900,000 possible values, drawn from a Mersenne Twister whose entire
     19,968-bit state is recoverable from 624 consecutive observed draws. This
     is the real problem: it does not care what the seed was.

  2. randint() burns state unpredictably
     randrange() draws 20 bits and *redraws* if the value lands outside the
     range - about 14% of the time here. So the state words consumed per call
     vary, which is why 6-digit output is not a clean 624-word block. It is
     still completely predictable; the alphabet is what kills it.

  3. random.seed(time.time())
     ~53 bits of known-structure entropy: 31 from the integer second, 22 more
     from the float fraction (4,194,304 distinct floats per second, since the
     ULP at t~1.8e9 is 2^-22). Measured here: ~113,000 seeds/sec in pure
     Python, so a one-second window costs ~37 CPU-seconds; in C, far less.
     Crackable, but NOT the instant win people claim.

     Pass --seed-mode int to model the far more common
     `random.seed(int(time.time()))`, which really is ~2^31 and really is an
     instant sweep of the seconds around a known timestamp.

  4. The MT state is shared process-wide
     Anything else in the same process that draws from `random` is correlated
     with these numbers. --leak demonstrates exactly that.

Measured on this script, 1000 numbers, 1.15 state words per number (153
rejections in 1153 words), and every number reproduced exactly from a 624-word
leak alone. See README.md for the end-to-end crack.

The correct version of this script uses `secrets` and no seeding at all. See
INSECURE-RANDOMNESS.md.
"""

import argparse
import os
import random
import sys
import time

VERSION = "1.0.0"
PROG = os.path.basename(sys.argv[0]) or "gen-weak.py"

# The digit range. 100000-999999 is exactly six digits, no leading zeros.
LOW = 100_000
HIGH = 1_000_000  # exclusive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Generate deliberately insecure random numbers (testing only).",
        epilog=(
            "example:\n"
            f"  {PROG} > numbers.txt                   1000 weak six-digit numbers\n"
            f"  {PROG} --count 5000 --out big.txt     more of them\n"
            f"  {PROG} --leak leak.txt > numbers.txt   also emit a 624-word state leak\n"
            f"\n"
            "then crack it:\n"
            f"  {PROG.replace('gen-weak.py', 'mtpredict')} leak.txt --guess 900\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-n", "--count", type=int, default=1000, metavar="N",
        help="how many numbers to generate (default: 1000)",
    )
    parser.add_argument(
        "-o", "--out", metavar="FILE",
        help="write numbers to FILE instead of stdout",
    )
    parser.add_argument(
        "--leak", metavar="FILE",
        help="also write 624 consecutive getrandbits(32) values to FILE, taken "
             "from the same generator BEFORE the numbers (so mtpredict can "
             "recover the state and predict what follows)",
    )
    parser.add_argument(
        "--seed", type=float, metavar="T",
        help="seed explicitly with T instead of the current time",
    )
    parser.add_argument(
        "--seed-mode", choices=("float", "int"), default="float",
        help="'float' (default) seeds with the full time.time(), ~2^53. 'int' "
             "models the common random.seed(int(time.time())) mistake, ~2^31, "
             "which is instantly brute-forceable from a known timestamp",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {VERSION}",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.count < 0:
        print(f"{PROG}: error: --count must be zero or greater", file=sys.stderr)
        return 1

    # --- WEAKNESS 3: the seed is the clock -----------------------------------
    if args.seed is not None:
        seed_value = args.seed
    elif args.seed_mode == "int":
        # Models random.seed(int(time.time())) - ~2^31, instantly crackable.
        seed_value = int(time.time())
    else:
        seed_value = time.time()
    random.seed(seed_value)
    print(
        f"{PROG}: seeded with {seed_value!r} "
        f"[{args.seed_mode} mode, insecure on purpose - see the module docstring]",
        file=sys.stderr,
    )

    # --- the state leak, drawn first so mtpredict can predict the numbers ----
    if args.leak:
        try:
            with open(args.leak, "w", encoding="utf-8") as handle:
                handle.write("# 624 consecutive getrandbits(32) from the same\n")
                handle.write("# generator that produced the six-digit numbers.\n")
                for _ in range(624):
                    handle.write(f"{random.getrandbits(32)}\n")
        except OSError as exc:
            print(f"{PROG}: cannot write {args.leak}: {exc.strerror}", file=sys.stderr)
            return 2
        print(
            f"{PROG}: wrote 624-word state leak to {args.leak}",
            file=sys.stderr,
        )

    # --- WEAKNESS 2 & 3: tiny range, rejection-sampled draws -----------------
    numbers = [random.randint(LOW, HIGH - 1) for _ in range(args.count)]

    # --- output --------------------------------------------------------------
    payload = "".join(f"{n}\n" for n in numbers)
    try:
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"{PROG}: wrote {args.count} number(s) to {args.out}", file=sys.stderr)
        else:
            sys.stdout.write(payload)
            sys.stdout.flush()
    except OSError as exc:
        print(f"{PROG}: cannot write output: {exc.strerror}", file=sys.stderr)
        return 2

    if not args.out:
        print(
            f"{PROG}: {args.count} number(s) on stdout "
            f"(range {LOW}-{HIGH - 1}, ~19.8 bits each)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        sys.exit(0)
