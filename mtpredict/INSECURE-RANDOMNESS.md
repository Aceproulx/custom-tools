# Insecure Randomness: A Catalogue

Every pattern below generates weak randomness that `mtpredict` — or a much
simpler brute force — can defeat. Each entry shows the bad code, why it fails,
how it gets attacked, and the fix.

Use this two ways:

- **Auditing** — grep your codebase for these patterns.
- **Learning** — the point of each entry is the *fix*, not the novelty.

> **Scope.** Everything here is about defending your own systems and CTF
> material. Don't point any of it at systems you have no permission to test.

---

## The one rule

> If the value is a **secret** (password, token, key, nonce, IV, session
> secret, OTP, CSPRNG seed) or the value decides something **valuable**
> (lottery, shuffle, game, ranking), it must come from `secrets` / `os.urandom`
> / `crypto/rand`. `random` is for everything else.

`random` is not "slower crypto". It is MT19937: a fixed, publicly documented
algorithm with 19,968 bits of state that *outputs leak back*. `secrets` is a
thin wrapper over the OS CSPRNG and leaks nothing.

---

## 1. Seeding from the clock

The most widespread mistake. The seed is the only secret, and here it is the
current time.

```python
import random, time

def session_token():
    random.seed(time.time())                       # time is the secret
    return ''.join(random.choice('abcdef0123456789') for _ in range(32))
```

**Attack: how weak depends on the exact call, and people get this wrong in both
directions.**

| seeding call | seed space | how it breaks |
|---|---|---|
| `random.seed(int(time.time()))` | ~2³¹ (1 s resolution) | instant — sweep the seconds |
| `random.seed(int(time.time()) // 60)` | ~2²⁵ (1 min resolution) | instant |
| `random.seed(time.time())` | ~2⁵³ (float) | minutes of CPU per second-window |
| `random.seed()` on a truncated string | depends | depends on truncation |

`int(...)` is the classic crack and is genuinely instant — the integer seconds
around a known timestamp are a tiny space:

```python
# attacker, against seed(int(time.time()))
for delta in range(-86400, 86401):
    random.seed(now + delta)
    if make_token() == stolen: found_it = now + delta
```

The bare `time.time()` float is **not** that easy, and claiming otherwise is
sloppy in the other direction. At t≈1.79e9 the ULP is 2⁻²², so each integer
second contains 4,194,304 distinct float values — about 22 extra bits. Measured
here: ~113,000 seeds/sec in pure Python, so a one-second window costs roughly
37 CPU-seconds; in C it's about a thousand times faster. An attacker who knows
the generation time to within a few seconds (an `HTTP Date` header, a log
line, a request timestamp) turns that into a routine offline crack, not a
forensic project.

So: don't quote "31 bits" for `time.time()` and don't call it uncrackable
either. It's ~53 bits of *known-structure* entropy, which is the worst
combination — enough to look fine, little enough to sweep. Truncating to an
integer makes it trivial.

Two more details that bite in practice: a service that reseeds per request in a
tight loop produces the *same* stream for every request within the same second
(so two tokens issued in one second share a generator), and the weakness
compounds with the rest of this document — even a perfect seed buys you nothing
if the state is then used to produce a 32-character `random.choice` token.

**Fix:** don't seed at all.

```python
import secrets
def session_token():
    return secrets.token_urlsafe(32)
```

Same trap in other languages:

```
random.seed(datetime.now().timestamp())   # Python
Math.seed(new Date().getTime())           // JS
srand(time(NULL));                         // C
rand.Seed(time.Now());                     // Go
new Random(System.currentTimeMillis())     // Java
```

### Also: deterministic seeds in shipped code

```python
random.seed(42)          # every install generates the same "random" numbers
random.seed("hunter2")
random.seed(user_id)     # attacker controls this and can enumerate
```

Seeding is for *reproducibility* — test fixtures, simulations, ML splits. If
you want reproducible randomness, `random.Random(seed)` gives you an isolated
instance and is the right tool. Never in a secret-producing path.

---

## 2. Passwords, tokens, and API keys from `random`

The most damaging category, because these are the highest-value secrets.

```python
import random, string

def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

def generate_api_key():
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))
```

**Why it's broken, three ways at once:**

1. **State recovery.** One `getrandbits(32)` → one state word. Get 624 of them
   and the entire stream is cloned. `mtpredict` does this.
2. **Tiny alphabet.** 12 chars from 62 = ~71 bits *at best* — and that assumes
   the generator is actually uniform, which MT is not after state recovery.
   The hex key above is 128 bits nominal but only ~71 bits of real unpredictability
   once the state is known.
3. **Rejection sampling leaks bits.** `random.choice` is literally
   `seq[self._randbelow(len(seq))]`, and `_randbelow` is
   `getrandbits(n.bit_length())` in a redraw loop — so each `choice` consumes a
   variable number of state words. The recovery is therefore no longer a clean
   624-word block you can hand to `mtpredict` — but the alphabet is the real
   problem, not the recovery.

**Attack:** leak 624 `getrandbits(32)` values from the same process, hand them
to `mtpredict`, then predict every password that process will ever generate.

**Fix:**

```python
import secrets
def generate_password(length=20):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_api_key():
    return secrets.token_hex(32)          # 256 bits from os.urandom
```

If humans must type it, entropy per character is what matters — length beats
alphabet size. `secrets.token_urlsafe(32)` is the safe default for machine
tokens.

---

## 3. Shuffling something that matters

Fisher–Yates on an MT-backed generator is still fully determined by the state.

```python
import random
def shuffle_deck(deck):
    random.shuffle(deck)                  # not a fair shuffle
    return deck
```

Used for: card games, lotteries, auction order, "pick a random winner from the
signups list", test-case ordering that gets shipped, quiz answer shuffling.

**Attack:** once the state is recovered, the *entire permutation* is known in
advance. A lottery using this is predictable before anyone buys a ticket.

**Fix:**

```python
import secrets
def shuffle_deck(deck):
    secrets.SystemRandom().shuffle(deck)  # SystemRandom == os.urandom
    return deck
```

`secrets.SystemRandom` is a drop-in replacement for the whole `random` API, so
the port is mechanical:

```python
rng = secrets.SystemRandom()
rng.random(); rng.randrange(10); rng.choice(xs); rng.shuffle(xs)
rng.getrandbits(32)
```

### Picking a winner

```python
winner = random.choice(entries)            # enumerable, predictable
```

```python
winner = secrets.choice(entries)
```

For a high-stakes draw, prefer a commit–reveal scheme: publish a seed hash
beforehand, then reveal the seed afterwards and let anyone verify. A `secrets`
call is unpredictable but still can't *prove* fairness after the fact.

---

## 4. OTPs, nonces, IVs, and salts

```python
def send_otp():
    return random.randint(0, 999_999)     # 10^6 possibilities, no rate limit

def make_nonce():
    return random.getrandbits(64)         # leaked state = future nonces

def make_iv():
    return os.urandom(8).hex().encode()   # ok-ish; never reuse
```

**`randint` for an OTP** is a rate-limiting problem more than a randomness
problem: a 6-digit code has 10^6 possibilities and will be reissued in
milliseconds without lockout.

The subtle part is that `randrange` doesn't draw 20 bits — it draws
`n.bit_length()` bits and *redraws* if the value lands outside `0..n-1`
(`random.Random._randbelow_with_getrandbits` in CPython). So a 6-digit OTP
burns 20 bits and rejects ~4.6% of the time, and the rejection count varies per
call. Measured:

| draw | bits/draw | state words per call |
|---|---|---|
| `randrange(10**6)` (6-digit OTP) | 20 | 1.05 |
| `randrange(10**4)` (4-digit) | 14 | 1.65 |
| `randrange(10**2)` (2-digit) | 7 | 1.29 |
| `randrange(1000)` | 10 | 1.02 (1,017 words over 1,000 calls) |

That variable consumption is exactly why `randrange` output can't be fed
straight into `mtpredict` — there's no aligned 624-word block, so the tool
*refuses* it (exit code 4) rather than inventing predictions. Passing
`--force` gives you numbers, just not true ones. It doesn't make the code safe:
the search space is still tiny and the bit leak is still there.

**Nonces and IVs** are unforgiving. A leaked nonce stream breaks
confidentiality outright — GCM with a repeated nonce leaks the authentication
key, which forges tags. There is no recovery from nonce reuse.

**Fix:**

```python
import secrets
def send_otp():
    return secrets.randbelow(1_000_000)   # 6-digit code, CSPRNG

def make_nonce():
    return secrets.token_bytes(8)

def make_iv():
    return secrets.token_bytes(12)        # 96-bit, fresh every message
```

If you need a *counter* rather than randomness, use a counter. If you need
uniqueness without secrecy, use a UUID or a database sequence.

---

## 5. Identifiers

```python
import uuid
def order_id():
    return str(uuid.uuid1())              # MAC address + 60-bit timestamp
```

`uuid1` encodes your MAC address and a timestamp. It is not a secret, but it is
a **mapping of who created what, when** — useful to an attacker for correlating
users, and it makes IDs guessable/enumerable.

```python
def session_id():
    return uuid.uuid4().hex              # fine, but see below
```

`uuid4` is genuinely random (it uses `os.urandom`) and fine as an opaque ID.
Prefer a prefixed random token for anything that grants access, so the value
carries no semantics:

```python
def session_id():
    return "sess_" + secrets.token_urlsafe(24)
```

Avoid: `hash(x)`, `md5(user_id)`, counters in a guessable order, and
`random`-based IDs. Use `uuid7` or a database sequence if you want
sort-by-creation ordering *plus* opacity.

---

## 6. Session secrets, signing keys, `SECRET_KEY`

```python
# Flask
app.secret_key = random.random()                       # 53 bits
app.secret_key = os.urandom(16).hex()                  # 128 bits, acceptable
```

```python
# Django
SECRET_KEY = "hardcoded-in-git"                        # not random at all
SECRET_KEY = hashlib.sha256(b"pepper").hexdigest()     # no entropy at all
```

**A framework session secret is a master key.** Anyone holding it can forge
session cookies, mint an admin session, and sign anything else the app signs
with it.

```python
SECRET_KEY = secrets.token_hex(64)   # 512 bits, per install
```

Store it in the environment or a secret manager — never in version control,
never derived from a fixed string. If a static pepper is genuinely required
(it usually isn't), get it from the environment too.

---

## 7. DIY "CSPRNGs" that aren't

Hash functions are *not* PRNGs. These all look sophisticated and all fail:

```python
# SHA-256 in counter mode - the classic mistake
state = hashlib.sha256(b"seed").digest()
def byte():
    global state
    state = hashlib.sha256(state).digest()   # hash chain, not a PRNG
    return state[0]
```

```python
# Deterministic "random" from a hash of a counter
def token(i):
    return hashlib.sha256(f"{i}".encode()).hexdigest()   # fully enumerable
```

```python
# mt19937ar.js ported to Python - same state-recovery problem
```

**Why the hash chain fails:** SHA-256's security assumption is that you *can't*
predict its output without knowing the input. A hash chain's entire state is the
last digest — the "secret" is the output, and generating a long run of outputs
leaks nothing you can't use. Worse, hash-function output is not statistically
uniform in the ways a PRNG needs, and there is no rekeying, so an observer
correlates outputs without end.

**Why the counter fails:** `sha256("1")`, `sha256("2")`, … is an infinite
predictable sequence. No key, no entropy. Anyone can compute your token.

**Fix — don't build it:**

```python
import secrets
token = secrets.token_urlsafe(32)                    # randomness

# keyed, deterministic-but-unpredictable, when you truly need reproducibility:
import hmac, hashlib
def mac(i: int) -> bytes:
    return hmac.new(key, i.to_bytes(8, "big"), hashlib.sha256).digest()
```

That last one is legitimate: HMAC-CTR / HKDF **is** a correct DRBG
construction, and it's what libraries implement. But reach for a library
(`cryptography`) rather than hand-rolling it — the ways to get this subtly wrong
are numerous and quiet.

---

## 8. Other languages

The bug is language-agnostic. Equivalent landmines:

```javascript
// JS — every one of these is reversible
Math.random()                              // xorshift128+, state recoverable
function token() { Math.seed(Date.now()); return Math.random() }
[1,2,3].sort(() => Math.random() - 0.5)     // broken AND biased
```

```java
new Random()                               // seeded from clock + pid
new Random(System.currentTimeMillis())
RandomGenerator.getDefault()               // deprecated, seeded from time
```

```php
rand(); mt_rand(); array_rand();           // mt_rand is recoverable given 624 outputs
```

```go
rand.Seed(time.Now().UnixNano())           // deterministic and enumerable
```

```c
srand(time(NULL));
rand() % 6                                 // also modulo bias
```

JS's `Math.random()` is a 128-bit xorshift128+; 624+ consecutive outputs are
enough to recover it and predict forward. The fixes are `crypto.getRandomValues`
in the browser and `crypto.randomBytes` in Node.

`sort(() => Math.random() - 0.5)` deserves its own warning: the comparator is
inconsistent, so V8's sort does not produce a uniform permutation even in
principle. Use Fisher–Yates with a CSPRNG.

---

## 9. Timing and comparison

Adjacent to randomness, and just as exploitable:

```python
if submitted == stored_token:               # timing leak
    login()
```

```python
if hashlib.md5(password).hexdigest() == stored_hash:   # MD5, and timing
    login()
```

```python
if user_pin == submitted_pin:              # trivial timing leak + no rate limit
    grant_access(user)
```

**Fixes:**

```python
import hmac, hashlib, secrets

# constant-time comparison
if hmac.compare_digest(submitted, stored_token):
    login()

# password storage: a KDF, not a fast hash
hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
# or: argon2-cffi, bcrypt, scrypt from a vetted library
```

Rate-limit and lock out on guesses. `compare_digest` is
`hmac.compare_digest`; `secrets.compare_digest` is an alias for convenience.

---

## Finding these in your own code

```bash
# the highest-signal greps
grep -rn 'random\.seed'          --include='*.py'
grep -rn 'seed(.*time\|seed(.*now' --include='*.py'
grep -rn 'uuid\.uuid1\|uuid1('   --include='*.py'
grep -rn 'Math\.random\|Math\.seed' --include='*.js'
grep -rn 'srand\|rand()'         --include='*.c'
grep -rn 'math/rand'             --include='*.go'
grep -rn 'mt_rand\|array_rand'   --include='*.php'
grep -rn 'secret_key\s*=\|SECRET_KEY\s*=' --include='*.py'
```

Then the real test: find every call site that produces a secret and ask what
*specifically* would break if the value were predictable. Most of the time the
answer is "an attacker authenticates as anyone" or "an attacker forges
sessions", which is how you prioritise the fix.

### The end-to-end attack, in three commands

If a process ever emits 624 consecutive `getrandbits(32)` values, everything it
generates afterwards is known:

```bash
# 1. capture 624 values from the target process
python3 -c "import random; [print(random.getrandbits(32)) for _ in range(624)]" > leak.txt

# 2. recover state, predict the next 100
mtpredict leak.txt --guess 100

# 3. use them
```

If you can't get a clean 624-word block, you usually don't need one. Partial
observation is enough when the seed space is small (`random.seed(42)`), when the
generator is an LCG, or when the values are `random.random()` floats — 624
floats give a Z3/GF(2) solver 1248 word-constraints on 624 unknowns, massively
overdetermined.

---

## The fix, in one table

| Bad | Good |
|---|---|
| `random.seed(time.time())` | don't seed |
| `random.seed(42)` in production | `random.Random(42)` for tests only |
| `random.choice(alphabet)` for a secret | `secrets.choice(alphabet)` |
| `''.join(random.choices(...))` for a token | `secrets.token_urlsafe(32)` |
| `random.randrange(10**6)` for an OTP | `secrets.randbelow(10**6)` |
| `random.shuffle` on anything valuable | `secrets.SystemRandom().shuffle` |
| `random.random()` for a key | `secrets.token_bytes(32)` |
| `random.getrandbits(64)` for a nonce | `secrets.token_bytes(8)` |
| `uuid.uuid1()` for an ID | `uuid.uuid4()` / `uuid7` |
| `os.urandom(4)` for an IV | `secrets.token_bytes(12)`, never reused |
| `hashlib.sha256(state)` as a PRNG | a library (`cryptography`) |
| `sha256(str(counter))` as a token | `hmac.new(key, ...)` or `secrets` |
| `app.secret_key = random.random()` | `secrets.token_hex(64)` from env |
| `SECRET_KEY` in git | env var / secret manager |
| `token == submitted` | `hmac.compare_digest` |
| `md5(password)` | `hashlib.scrypt` / argon2 / bcrypt |
| `Math.random()` | `crypto.getRandomValues` |
| `srand(time(NULL))` | read from `/dev/urandom` |
| `[..].sort(() => Math.random()-0.5)` | CSPRNG Fisher–Yates |

And where `random` is still correct: shuffling a list for your own UI,
Monte Carlo simulation, sampling a dataset for an ML split, generating test
fixtures. Determinism is the *point* there. The question is never "is `random`
safe" — it's "is this value a secret, or does it decide something valuable".

---

## Further reading

- Python `random` module docs — the warning at the top says it outright
- `secrets` module docs
- Erik Bosman, *Recovering the full state of the Mersenne Twister* (2013)
- Schneier & Ferguson, *Cryptanalysis of the Mersenne Twister PRNG* (2008)
- NIST SP 800-90A/B/C — approved entropy sources and DRBG constructions
