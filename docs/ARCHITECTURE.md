# Architecture

privkit is a single Python package with five functional subpackages and a thin CLI. Every
subpackage can be used on its own. The only cross-package links are that `tokens` builds on
`fpe` and `keys`, that `pii.anonymize` can call `tokens`, and that `evaluation` exercises `pii`.

```
src/privkit/
├── errors.py            exception hierarchy (PrivkitError and subclasses)
├── checksums.py         Luhn, IBAN mod-97, ABA, Verhoeff, NHS mod-11 (validate + generate)
├── keys.py              key parsing (hex/base64), env loading, HKDF-SHA256 derivation
├── fpe/                 NIST SP 800-38G
│   ├── alphabet.py      Alphabet: chars <-> numerals, radix 2..2^16
│   ├── _numeral.py      NUM / STR / NUM_radix, min-domain rule, AES block + CBC-MAC
│   ├── ff1.py           FF1 (Algorithms 7 and 8)
│   ├── ff3_1.py         FF3-1 (Rev. 1, Algorithms 9 and 10)
│   └── cipher.py        FormatPreservingCipher: string API over either algorithm
├── tokens.py            TokenPolicy + Tokenizer (vaultless, format-preserving, reversible)
├── pii/
│   ├── model.py         Entity enum, Finding (value-hiding repr)
│   ├── validators.py    per-entity validators (accept / trim / reject candidates)
│   ├── recognizers.py   PatternRecognizer table: regex, base score, context words
│   ├── detector.py      Detector: candidates -> context scoring -> overlap resolution
│   ├── ner.py           optional spaCy adapter (lazy import)
│   ├── anonymize.py     Redact / Mask / Pseudonymize / Tokenize operators, detokenize_text
│   └── structured.py    column-level scanning with header-word context
├── kanon/
│   ├── metrics.py       equivalence classes, k, l-diversity, t-closeness, risk
│   ├── hierarchy.py     interval / masking / mapping / suppression hierarchies
│   ├── generalize.py    minimum-loss full-domain generalization (lattice search)
│   └── mondrian.py      Mondrian multidimensional partitioning
├── dp/
│   ├── rng.py           secure (SystemRandom) and explicitly-insecure seeded RNGs
│   ├── _exact.py        exact Bernoulli(exp(-g)), discrete Laplace, discrete Gaussian
│   ├── accounting_math.py  analytic Gaussian, RDP curves, conversions, advanced composition
│   ├── mechanisms.py    Laplace, DiscreteLaplace, Gaussian, DiscreteGaussian
│   ├── accountant.py    PrivacyAccountant, Charge ledger, JSON persistence
│   └── aggregate.py     DPAggregator: bounding, partition selection, count/sum/mean
├── evaluation/          synthetic labeled corpus + strict span metrics
├── io.py                CSV / JSONL / text I/O with "-" for stdio
└── cli.py               argparse CLI
```

## 1. Format-preserving encryption (`privkit.fpe`)

Both algorithms are Feistel networks over *numeral strings* (integers in `[0, radix)`).
The code mirrors the pseudocode of SP 800-38G Rev. 1 line by line, so it can be audited
against the standard.

### FF1 (10 rounds)

For an input of length n: u = ⌊n/2⌋, v = n − u, A = X[1..u], B = X[u+1..n].
b = ⌈⌈v·log₂ radix⌉ / 8⌉ is computed exactly as `((radix**v - 1).bit_length() + 7) // 8`,
which avoids floating-point logarithms. d = 4⌈b/4⌉ + 4.
P = [1,2,1] ‖ [radix]³ ‖ [10] ‖ [u mod 256] ‖ [n]⁴ ‖ [t]⁴.
Round i: Q = T ‖ 0^((−t−b−1) mod 16) ‖ [i] ‖ [NUM_radix(B)]^b, R = CBC-MAC_K(P ‖ Q).
S is the first d bytes of R ‖ E_K(R ⊕ [1]) ‖ E_K(R ⊕ [2]) ‖ …, and
C = (NUM_radix(A) + NUM(S)) mod radix^m with m = u or v by parity. Then A ← B, B ← C.

### FF3-1 (8 rounds)

u = ⌈n/2⌉. The 56-bit tweak is split into T_L = T[0..27] ‖ 0⁴ and
T_R = T[32..55] ‖ T[28..31] ‖ 0⁴. Round i uses W = T_R on even rounds and T_L on odd
rounds, P = (W ⊕ [i]⁴) ‖ [NUM_radix(REV(B))]¹², and
S = REVB(E_REVB(K)(REVB(P))). maxlen = 2⌊log_radix 2⁹⁶⌋, computed with integer arithmetic.

### Constraints enforced

radix ∈ [2, 2¹⁶]; radix^minlen ≥ 10⁶ (DomainTooSmallError); FF1 maxlen 2³²; FF3-1 tweak
exactly 7 bytes; AES keys of 16, 24 or 32 bytes.

**Cost per call:** FF1 makes 10 × (⌈(|P|+|Q|)/16⌉ + ⌈d/16⌉ − 1) AES block operations.
FF3-1 makes 8. The big-integer NUM/STR conversions are O(n²) digit operations, which is
negligible for identifiers (n < 60).

**Verification:** the 9 NIST CSRC FF1 samples plus 1,200 ACVP vectors
(`tests/unit/test_fpe_vectors.py`), and Hypothesis round-trip properties on random keys,
radixes, lengths and tweaks.

## 2. Tokenization (`privkit.tokens`)

`Tokenizer(master_key, policies)` maps `(value, policy)` to a token:

1. **Normalize** (optional: lowercase or uppercase, e.g. MAC, IBAN). Applied on tokenize only.
2. **Region:** `span_pattern` picks the substring to protect (EMAIL: the local part).
3. **Positions:** indices inside the region whose characters are in the policy alphabet.
   All other characters (separators, `@`, dots) stay where they are.
4. **Luhn handling** (`LuhnMode.VALID`/`INVALID`): the last digit is taken out, the body is
   encrypted, and a check digit is recomputed. That makes tokens pass, or deliberately fail,
   Luhn. Detokenization recomputes the original check digit.
5. **Keep prefix/suffix** characters in the clear (CREDIT_CARD keeps the last 4).
6. **Domain check:** radix^|encrypted| ≥ 10⁶, otherwise `DomainTooSmallError`.
7. **Key:** `HKDF-SHA256(master, info="privkit/v1/token/<alg>/<policy name>")`. Each policy,
   and each column in `tokenize-table`, gets an independent AES-256 key.
8. **Tweak:** `SHA-256("privkit-tweak|<policy>|<kept prefix>|<kept suffix>")`, truncated to
   16 bytes (FF1) or 7 bytes (FF3-1). Binding the kept characters means two cards that share
   their last four digits are still encrypted under different permutations.

The **IP codec** encrypts IPv4 as 4 numerals of radix 256 and IPv6 as 8 numerals of radix
65,536, so the token is always a syntactically valid address of the same family.
`keep_prefix` keeps leading octets or hextets, for example to preserve a /8.

**Tagged tokens** (`[[ENTITY:token]]`) make free-text tokenization reversible:
`detokenize_text` finds the tags and inverts each token with the policy named in the tag.

## 3. PII detection (`privkit.pii`)

```
text ──► for each PatternRecognizer: regex.finditer ──► validator(candidate)
             │                                          ├─ None: drop
             │                                          └─ n: keep candidate[:n]
             ▼
       context scoring: base_score
         + boost   if a context word appears within 6 words before / 3 after
         − penalty if a negative cue is among the 2 words immediately before
       (window stops at sentence boundaries [.!?;]\s or \n, and at any other
        number of 3+ digits: "SSN: 719-01-7182 Order 768446870" gives the cue
        only to the first number)
             │
             ▼  keep score ≥ threshold (0.5)        + span recognizers (spaCy NER)
       resolve_overlaps: greedy by (score desc, length desc, start)
             ▼
       non-overlapping Findings sorted by start
```

Base scores encode how much a pattern can be trusted without context. Luhn + IIN-valid
cards and mod-97-valid IBANs score 0.8 or higher and are reported on their own. A bare
9-digit number scores 0.2 as an SSN and 0.25 as an ABA routing number, so it is only
reported next to "ssn", "social security", "routing" and similar words.

`resolve_overlaps` keeps a sorted list of accepted intervals and checks each candidate's
neighbours with `bisect`: O(m log m) comparisons for m candidates.

**Structured scanning** runs the detector on each cell and passes the column header's words
as `context_hint`. That is how a `customer_ssn` column of bare 9-digit numbers gets
classified correctly. A column is labelled with its dominant entity when that entity is
found in at least 30% of non-empty sampled cells.

**Overall cost:** O(R·n) regex scanning for R = 16 recognizers over n characters, plus
validator cost proportional to the candidate length.

## 4. k-anonymity (`privkit.kanon`)

* `assess` hashes each row's QI tuple into equivalence classes in O(n). k is the smallest
  class size. Prosecutor risk is 1/k (maximum) and #classes/n (average). Distinct and
  entropy l-diversity and t-closeness are computed per class. t-closeness uses total
  variation for categorical attributes and ordered EMD (Li et al. 2007, ground distance
  |i−j|/(m−1)) for numeric ones.
* `generalize_to_k` enumerates the full-domain generalization lattice Π(hᵢ+1) in order of
  increasing Prec loss (mean of level/height). Prec loss is monotone along lattice edges,
  so the first feasible node is a minimum-loss solution, and a test checks this by brute
  force. A node is feasible if the records in classes smaller than k number at most
  `max_suppression · n`. Those records are removed. Generalized columns are precomputed
  once per (QI, level), so each node costs one O(n) zip-and-count. Worst case:
  O(n · Π(hᵢ+1)).
* `mondrian` (LeFevre et al. 2006, strict) maps every QI to a float coordinate (categorical
  values by sorted rank), then repeatedly splits the partition at the median of the
  dimension with the widest normalized span, provided both halves keep ≥ k records.
  Leaves become classes: numeric QIs become `[min-max]` using the original strings, and
  categorical QIs become `a|b|c`. Expected cost is O(n log² n). Reported quality metrics:
  discernibility Σ|E|² and normalized certainty penalty.

## 5. Differential privacy (`privkit.dp`)

### Mechanisms

| mechanism | noise | calibration | guarantee | RDP curve used by the accountant |
|---|---|---|---|---|
| `LaplaceMechanism` | Lap(Δ₁/ε), from the difference of two Exp(1) draws | b = Δ₁/ε | ε-DP | Mironov 2017 Prop. 6 (exact) |
| `DiscreteLaplaceMechanism` | P(z) ∝ e^(−\|z\|ε/Δ₁), exact | scale rounded *up* to a rational | ε-DP | min(ε, αε²/2) |
| `GaussianMechanism` | N(0, σ²) | analytic (Balle & Wang 2018, bisection on the exact δ(ε) profile) or classic | (ε, δ)-DP | αΔ₂²/(2σ²) |
| `DiscreteGaussianMechanism` | P(z) ∝ e^(−z²/2σ²), exact | σ² rounded up; σ from ε = ρ + 2√(ρ ln 1/δ) | ρ-zCDP, ρ = Δ₂²/2σ² | αρ |

**Exact samplers** (`_exact.py`, Canonne, Kamath & Steinke 2020, Algorithms 1-3) use only
integer and `Fraction` arithmetic:

* Bernoulli(p) for rational p: `randrange(den) < num`.
* Bernoulli(e^(−γ)): for γ ≤ 1, count K while Bernoulli(γ/K) succeeds and return K odd.
  For γ > 1, take ⌊γ⌋ Bernoulli(e^(−1)) trials, then one for the fractional part.
* Discrete Laplace(t/s): U uniform in [0, t), accepted with probability e^(−U/t); V is
  geometric from Bernoulli(e^(−1)); Y = ⌊(U + tV)/s⌋; a random sign, rejecting −0.
* Discrete Gaussian(σ²): propose Y ~ DLap(⌊σ⌋+1) and accept with probability
  Bernoulli(exp(−(|Y| − σ²/t)²/2σ²)).

All of them take O(1) expected trials per sample. The default RNG is `secrets.SystemRandom`.

### Accountant

`PrivacyAccountant(ε_budget, δ_budget, composition)` keeps a ledger of `Charge`s (label,
mechanism, (ε, δ), optional RDP curve on a fixed order grid of 29 orders from 1.25 to 1024).
`spent()` is the minimum over the valid composition rules:

* basic: (Σεᵢ, Σδᵢ);
* advanced (Kairouz et al. heterogeneous form): √(2 ln(1/δ′)·Σεᵢ²) + Σεᵢ(e^εᵢ − 1), with
  δ′ = δ_budget − Σδᵢ;
* RDP: Σ RDPᵢ(α) over the charges that have curves, converted with
  ε = RDP(α) + ln((α−1)/α) − (ln δ′ + ln α)/(α−1) (Canonne-Kamath-Steinke 2020 Prop. 12),
  plus basic composition of the curveless charges (partition selection).

`charge(*charges)` holds a lock, computes the composed cost including the new charges, and
records them only if that cost stays within budget. Otherwise it raises
`BudgetExceededError`. The JSON ledger is written to a temp file and renamed for atomicity.

### Aggregation pipeline (`DPAggregator`)

1. **Contribution bounding:** group records by privacy unit, keep ≤ L0 random partitions
   per unit and ≤ L∞ random records per partition, and clamp values to `[lower, upper]`.
   O(n).
2. **Budget split:** if keys are not public, ε_sel = ε/3 goes to partition selection with
   δ_sel = δ (all of δ for Laplace, half for Gaussian), and ε − ε_sel goes to the query.
   Mean splits the query budget in half between a count and a centered sum.
3. **Sensitivity:** count L1 = L0·L∞ (L2 = √L0·L∞). Sum L1 = L0·L∞·max(|lo|, |hi|).
   Centered sum L1 = L0·L∞·(hi−lo)/2.
4. **Mechanism choice:** Laplace family → discrete Laplace for counts and for sums declared
   `integer=True` (integer bounds, values rounded after clamping), continuous Laplace
   otherwise. Gaussian family → discrete Gaussian or analytic Gaussian on the same rule.
   The choice uses public arguments only, never the records.
5. **Charge** all parts atomically. Only then sample.
6. **Partition selection:** release key p iff distinct_units(p) + Z ≥ 1 + k with
   Z ~ DLap(L0/ε_sel) and k the smallest integer with q^k/(1+q) ≤ δ_sel/L0, where
   q = e^(−ε_sel/L0). A test checks the bound and that k is minimal.
7. **Post-processing:** counts are rounded and clamped at 0. Mean = mid + noisy centered
   sum / max(noisy count, 1), clamped to the range. A delta-method standard error is
   computed from the noisy values only.

Total cost: O(n + P) time and O(n) memory for n records and P partitions.

## 6. Evaluation harness (`privkit.evaluation`)

`generate_corpus(split, n_docs, seed)` fills sentence templates from one of two disjoint
pools (27 templates each). Every labelled value is valid by construction, using the
same check-digit generators that `checksums.py` exports. Hard negatives are unlabelled
slots: Luhn-invalid cards, impossible SSNs, bad-check-digit IBANs, version strings,
9-digit order numbers and non-birth dates. `evaluate` computes strict (type, start, end)
precision, recall and F1 per entity, and only scores the entity types the detector
configuration attempts.

## 7. Error handling and logging

Library errors derive from `PrivkitError` (`InvalidInputError`, `DomainTooSmallError`,
`KeyMaterialError`, `BudgetExceededError`, `ConfigurationError`,
`OptionalDependencyError`). Messages never contain the offending value. Modules log through
`logging.getLogger("privkit.*")` and only log counts, entity types and parameters.
`Finding.__repr__` hides the matched text, and a test asserts that values do not appear in
captured logs.
