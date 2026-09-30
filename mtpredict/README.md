# mtpredict

Recover Python's `random` (Mersenne Twister MT19937) internal state from **624
consecutive 32-bit outputs**, then predict the values that come next.

```console
$ mtpredict 624_numbers.txt --guess 100
mtpredict: state recovered from 624 words, predicted 100 value(s) on stdout
1083100347
3410042571
603375972
...
```

Zero dependencies. Single file. Python 3.8+.

## Layout

```
custom-tools/
└── mtpredict/
    ├── mtpredict                 the tool (executable, no dependencies)
    ├── gen-weak.py               insecure data generator, for testing
    ├── README.md                 this file
    ├── INSECURE-RANDOMNESS.md    companion: code that shouldn't exist
    └── examples/
        └── 624_numbers.txt       sample observation file
```

## Install

Already runnable from its directory — no build, nothing to install:

```bash
cd custom-tools/mtpredict
./mtpredict --selftest                # verify it works
```

It is also already symlinked onto your `PATH` at
`~/.local/bin/mtpredict`, so you can call it by name from anywhere:

```bash
mtpredict --selftest
```

To re-create that link, or to install it somewhere else:

```bash
ln -sf "$PWD/mtpredict" ~/.local/bin/mtpredict
```

## Usage

```bash
cd custom-tools/mtpredict

mtpredict 624_numbers.txt --guess 100     # predict the next 100 values
mtpredict capture.txt --guess 10 --out p.txt
cat capture.txt | mtpredict - --guess 5   # read from stdin
mtpredict --demo                          # write a fresh sample file
mtpredict --selftest                      # verify against real `random`
```

Predictions go to **stdout** (one per line, so the tool pipes cleanly); the
report goes to stderr. `--quiet` silences the report.

### Flags

| Flag | Meaning |
|---|---|
| `-g, --guess N` | how many values to predict (default 10) |
| `-o, --out FILE` | write to a file instead of stdout |
| `--head` | file has >624 numbers: use the **first** 624 instead of the last |
| `--demo [FILE]` | generate a sample observation file |
| `--selftest` | verify the recovery against CPython's generator |
| `--force` | predict even if the input fails the `getrandbits(32)` sanity check |
| `-q, --quiet` | suppress the stderr report |
| `-V, --version` | print version |

Exit codes: `0` ok, `1` usage error, `2` file/IO error, `3` too few numbers,
`4` input is not `getrandbits(32)` output (see below).

### The input sanity check

The tool refuses to predict from input that cannot possibly be
`getrandbits(32)` output, because in that case every prediction is fiction.

The test is definitive rather than heuristic: genuine MT19937 words are uniform
over 32 bits, so **all 32 bit positions get set roughly half the time**. A bit
position that is never set across 64+ samples has probability 2⁻⁶⁴ — smaller than
a hardware error rate, so it is treated as proof of bad input, not a hint.

```bash
$ mtpredict numbers.txt --guess 10
mtpredict: error: input does not look like getrandbits(32) output: bit
positions 20-31 never set across 989 values
  ... (explains why, and how to capture the state properly)
```

It catches the usual mistakes — six-digit `randint`/`randrange` output,
`getrandbits(20)`, `random.random() * 10**6`, `getrandbits(8)`, and any scaled
or masked value. `--force` overrides it if you know something the check
doesn't.

Verified against 50,000 genuine `getrandbits(32)` streams: **zero** false
rejections, and all 5,000 sampled streams predicted exactly.

**Caveat worth knowing:** this catches *value-range* mistakes, not every
possible mistake. Values that are genuinely 32-bit but shuffled, offset, XORed,
or interleaved with other traffic will still pass the check and produce wrong
answers. The check narrows the field; it doesn't certify the input.

## Generate weak test data: `gen-weak.py`

`gen-weak.py` produces deliberately insecure numbers for exercising the tool.
It is a bad example on purpose — every weakness is documented in its
docstring and in [INSECURE-RANDOMNESS.md](INSECURE-RANDOMNESS.md).

```bash
./gen-weak.py                              # 1000 six-digit numbers to stdout
./gen-weak.py --count 1000 --out numbers.txt
./gen-weak.py --leak leak.txt --out numbers.txt   # also emit a 624-word state leak
./gen-weak.py --seed-mode int              # model random.seed(int(time.time()))
```

Numbers go to stdout, notes to stderr, so it pipes cleanly.

### The end-to-end crack

`--leak` dumps 624 consecutive `getrandbits(32)` values from the *same* weak
generator, before the six-digit numbers. That is all it takes — no seed
guessing required:

```bash
./gen-weak.py --count 1000 --leak leak.txt --out numbers.txt
./mtpredict leak.txt --guess 1500 --quiet > words.txt
```

`words.txt` holds the raw state words that followed the leak. The six-digit
numbers come out of `randrange` rejection sampling on those words, so recover
them by replaying that logic:

```python
words = [int(x) for x in open("words.txt")]
i, numbers = 0, []
while len(numbers) < 1000:
    val = words[i] >> 12          # getrandbits(20) from one 32-bit word
    i += 1
    if val < 900_000:             # redraw when the draw misses the range
        numbers.append(100_000 + val)

print(numbers == [int(x) for x in open("numbers.txt")])   # True
```

Verified on 1000 numbers: 1.15 state words consumed per number (153 redraws in
1153 words), all 1000 recovered exactly.

Note the two attacks are independent. The clock seed is recoverable *and* the
state is recoverable from a leak — the leak needs no seed at all, and works
under `--seed-mode int` too. Details and the float-vs-int seed distinction are
in [INSECURE-RANDOMNESS.md](INSECURE-RANDOMNESS.md) §1.

## Capturing the 624 numbers

The values **must be consecutive outputs of `getrandbits(32)`**:

```python
import random
with open("624_numbers.txt", "w") as f:
    for _ in range(624):
        f.write(str(random.getrandbits(32)) + "\n")
```

The file format is forgiving — one per line, space- or comma-separated, JSON-ish
lists, `#` comments and blank lines are all fine:

```
# 4 per line
2262295169 828566155 4017709064 1286202108
279203846 2348186595 1283345298 1222045728
```

### What breaks it

| Input | Works? | Why |
|---|---|---|
| `getrandbits(32)` × 624 | yes | one state word per value |
| `random.random()` × 624 | no | burns 2 words per call, and you lose 3 bits each |
| `randrange` / `randint` | no | rejection sampling consumes a *variable* number of words |
| `choice` | no | built on `randrange`, same problem |
| non-consecutive values | no | state is refilled every 624 words |

This is the single most common failure: `randint()` looks like it returns one
number, but internally it draws a 32-bit word and *rejects and redraws* if the
value is out of range, so the number of words consumed varies per call. Feed it
`getrandbits(32)` instead.

## If your file has more than 624 numbers

Every *aligned* block of 624 consecutive words reveals the state at that point.
With more than 624 values the tool uses the **last** 624 by default, which
predicts furthest past the end of your data. Use `--head` to take the first 624
instead and predict from that earlier point.

## How it works

Python's `random` module is MT19937, whose entire state is 624 × 32-bit words
(19,968 bits). Each output word is a *tempered* view of one state word:

```
y ^= y >> 11
y ^= (y <<  7) & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= y >> 18
```

`untemper()` inverts this to recover the raw state words, then the generator
twists forward one block (624 words) and emits the predictions.

Inverting the two **masked left shifts** is the only non-obvious part. Re-applying
the forward operation does *not* converge to the inverse. But forward, bit *i* of
the result is `b_i = a_i ^ (a_{i-s} & mask_i)`, which is triangular — so a single
low-to-high pass over the bits solves it exactly. The right shifts are order-2 and
order-4 xor-shifts, so `>>18` is its own inverse and `>>11` needs three
applications.

This is the technique Erik Bosman published in 2013, and the one
`pip install randcrack` wraps. This script implements it directly so there is
nothing to install.

## Verification

`--selftest` runs the full round trip against CPython's live generator:
recovering state from 624 real outputs and checking the next 10 values match,
plus a temper/untemper round trip and an explicit guard against a generator
that merely echoes its inputs back. It passes on Python 3.9 – 3.14.

## Scope

State recovery here only moves *forward* from the observed block. Predicting
values that came *before* your 624 requires untwisting the generator, which
`randcrack` implements via bit-trick unrotation — not included here.

## See also

**[INSECURE-RANDOMNESS.md](INSECURE-RANDOMNESS.md)** — the companion catalogue
of code that shouldn't exist: seeding from the clock, passwords from `random`,
shuffles, OTPs, `uuid1`, framework `SECRET_KEY`s, DIY hash-based "CSPRNGs", and
the same mistakes in JS/Java/PHP/Go/C. Each entry has the bad code, why it
fails, how it gets attacked, and the fix — plus grep patterns for auditing a
codebase and the measured state-word cost of each weak pattern.

## Legal use

For auditing randomness in systems you own or are authorised to test, CTFs,
security research, and forensics. Not for attacking systems you have no
permission to test.
