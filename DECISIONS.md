# Decisions

Format: `- Ruling: <what> — <why> — <cost if wrong>`.

## Scope and process

- Ruling: implement FF1 and FF3-1 directly from SP 800-38G Rev. 1 on top of `cryptography`'s AES block primitive, instead of wrapping a third-party FPE package — the spec asked for an implementation from the standard, and ~200 auditable lines verified against NIST vectors are better evidence than a dependency — a subtle bug would affect every token; mitigated by 1,200 ACVP vectors plus 9 CSRC samples plus round-trip property tests.
- Ruling: use the NIST ACVP-Server `internalProjection.json` files as the primary vector source, pinned to commit `b97fa5a`, alongside the 9 classic FF1 samples — they are official NIST data, cover all key sizes, several radixes and both directions, and also give FF3-1 vectors (the classic sample PDF only covers the superseded FF3) — if NIST revises the files, the pinned copies stay valid for the algorithm as standardized.
- Ruling: do not ship the original FF3 (64-bit tweak) — it is broken (Durak-Vaudenay 2017) and SP 800-38G Rev. 1 replaced it with FF3-1 — users with legacy FF3 tokens cannot detokenize them with privkit.
- Ruling: spaCy NER is an optional extra (`ner`), and the model wheel is installed by `make ner-model` — `make check` must pass offline from a fresh clone, and spaCy plus its model add ~40 packages; the adapter accepts any spaCy-like callable, so tests use a fake pipeline, and one real-model test skips when the model is absent — CI's default job never exercises the real model (a separate `ner` CI job does).
- Ruling: drop numpy from runtime dependencies; DP noise uses `secrets.SystemRandom` — Python's stdlib CSPRNG is the right default for privacy noise, and numpy's PCG64 is not a CSPRNG — per-sample Python loops are slower than vectorized numpy (fine for per-partition noise; see benchmarks).

## Tokenization

- Ruling: refuse format-preserving domains below 10⁶ values (`DomainTooSmallError`) rather than fall back to cycle-walking or a larger alphabet — SP 800-38G Rev. 1 sets radix^minlen ≥ 1,000,000 because small domains are open to codebook attacks — short fields (3-character email local parts, 5-digit dates) cannot be tokenized with the default policy; text mode redacts them instead and logs a warning (count only).
- Ruling: the DATE_OF_BIRTH policy encrypts letters and digits (alphabet ALNUM) — dates such as "August 7, 1962" hold only 5 digits (< 10⁶) — tokens no longer look like dates.
- Ruling: EMAIL keeps the domain and encrypts the local part, and EMAIL_FULL also encrypts the domain labels (TLD kept) — domain-level analytics are a common need, and EMAIL_FULL covers very short local parts — the domain stays visible under EMAIL.
- Ruling: CREDIT_CARD keeps the last 4 digits and binds them into the tweak; Luhn-valid or Luhn-invalid tokens are available through `LuhnMode` on custom policies — last-4 is the common display convention, and binding it into the tweak stops "same last four" values from sharing a permutation — 12 encrypted digits is still a 10¹² domain, but the last 4 are disclosed.
- Ruling: one HKDF-derived key per policy, and per column in `tokenize-table` (policy name `<POLICY>@<column>`) — prevents cross-column token correlation and limits the blast radius of a confused-deputy bug — the same SSN in two columns gets different tokens, so joins across columns need the same column policy name.
- Ruling: tokens are deterministic (no per-record nonce) — this preserves joins and group-bys on tokenized data, which is the main reason to tokenize instead of redact — equality and frequency leakage; documented in THREAT_MODEL.md.
- Ruling: text tokenization supports a tagged form `[[ENTITY:token]]` — untagged tokens are indistinguishable from real values, so text could not be detokenized reliably — tagged output is visibly not original text.

## Detection

- Ruling: regexes only propose candidates; a validator (checksum or structure) must accept them, and context words adjust the score against a 0.5 threshold — keeps precision high on numeric identifiers, which are the main sources of false positives — identifiers without checksums (bare 9-digit SSNs) need context to be reported, so recall drops in context-free tables (mitigated by header-word hints in `scan_columns`).
- Ruling: context windows stop at sentence boundaries and at the next 3+ digit number, and negative cues count only when they are among the 2 words immediately before the candidate — dev-split errors showed cues bleeding into neighbouring sentences and values ("SSN: 719-01-7182 Order 768446870") — a cue phrased after the value in another clause is missed.
- Ruling: card candidates right after "IBAN"/"BIC"/"SWIFT" are penalized — on the dev split an invalid IBAN's digits formed a Luhn-valid UnionPay number — a genuine card number written directly after the word "IBAN" would be missed (rare).
- Ruling: evaluate on a self-generated synthetic corpus with disjoint dev/test template pools and name lists; tune only on dev — no labeled PII dataset with a clearly compatible license was available offline, and real PII cannot be used — scores are optimistic upper bounds; disclosed in the README next to the numbers.
- Ruling: the held-out test split was first evaluated after the initial dev tuning rounds; two later fixes (context scoping, the IBAN cue) were driven by dev-split errors only — keeps the test split honest — the test split has been looked at, so it is not perfectly pristine; a fresh seed (`--seed`) gives new documents from the same held-out templates.
- Ruling: strict span matching (type + exact offsets) for precision and recall — this is the standard for de-identification evaluation and penalizes boundary errors — partial overlaps count as one FP plus one FN.

## k-anonymity

- Ruling: full-domain generalization searches the whole lattice in order of precision loss (first feasible node wins) instead of Incognito/Flash pruning — Prec loss is monotone along lattice edges, so this is exact, simple and fast for typical QI counts — exponential in the number of QIs (documented, O(n·Π(hᵢ+1))).
- Ruling: Mondrian treats categorical QIs by sorted rank ("relaxed ordering") and offers `categorical=` to force set generalization for codes like ZIP — avoids requiring taxonomies — lexicographic order may group semantically unrelated categories.
- Ruling: `RiskReport.to_dict()` omits class keys (QI values) unless asked — they are quasi-identifying data — less detail in default reports.

## Differential privacy

- Ruling: the user picks a noise *family* (Laplace = pure ε-DP, Gaussian = (ε, δ)); privkit uses the exact discrete sampler for counts and for sums declared `integer=True` (`--integer`), and the continuous one for other sums and for means — gives the floating-point-safe sampler wherever the caller says the query is integer-valued without a confusing four-way choice — real-valued sums keep the floating-point caveat.
- Ruling (fix round 1): the discrete-vs-continuous choice for a sum is made from public arguments only — an explicit `integer` flag (default False) that requires integer bounds and rounds each clamped value to the nearest integer — never from the records. The earlier code picked the discrete sampler when every kept value happened to be an integer; the integrality of the output then revealed whether a neighbouring record was non-integer, which voids ε-DP for those neighbours. An opt-in flag was preferred over "integer bounds ⇒ round and use discrete" because that would silently round real-valued data such as the demo's amounts — cost: integer sums now use the continuous sampler unless the caller passes the flag.
- Ruling: Gaussian calibration defaults to the analytic Gaussian mechanism (Balle & Wang 2018); the classic formula is opt-in and rejected for ε ≥ 1 — analytic calibration is tight and valid for every ε — none (classic is still available).
- Ruling: discrete Gaussian σ is calibrated through ρ-zCDP and the ρ + 2√(ρ ln 1/δ) conversion — simple and provably valid — slightly more noise than the tight discrete bound of CKS20 Theorem 7.
- Ruling: noise parameters are rationalized by rounding *up* (`rational_at_least`) — more noise never weakens privacy — up to 1e-6 relative extra noise.
- Ruling: private partition selection uses discrete-Laplace thresholding on distinct-unit counts with a union bound over L0 partitions, and takes 1/3 of ε (all of δ for Laplace, half of δ for Gaussian) — standard approach (Korolova et al. 2009; Wilson et al. 2020), simple to prove — not the most utility-efficient (Gaussian thresholding or weighted selection could keep more partitions).
- Ruling: the accountant reports the minimum over valid composition rules and only offers advanced/RDP for fixed (non-adaptive) parameter sequences; basic composition is the default — basic is the only one of the three that remains valid as a fully adaptive filter — users who pick RDP must not choose ε adaptively from noisy outputs (documented in DP_GUARANTEES.md).
- Ruling: a mean query is a noisy count plus a noisy centered sum (budget split 50/50), clamped to range — the centered sum halves the sensitivity relative to a raw sum — the delta-method CI is approximate, and labelled as such.
- Ruling: the RNG for contribution-bounding samples is the same secure RNG passed to the aggregator — subsampling must not depend on predictable randomness — none.
- Ruling: the CLI exposes `--insecure-seed` only for reproducible demos and tests, and it always logs a NOT-private warning — the demo output must be reproducible for the README — a user could misuse it; the flag name and the warning make the risk explicit.
- Ruling: the ledger is a JSON file with atomic replace and an in-process lock — no external service is needed for a CLI tool — it is not safe for concurrent processes sharing one file (documented).

## Engineering

- Ruling: Python 3.12, uv, ruff (format + broad lint set), `mypy --strict` over src, tests and scripts; coverage gate at 90% — matches the program contract (≥ 80% core) with headroom; measured coverage is 99% — a few defensive branches are tested indirectly.
- Ruling: the default `make check` excludes the NER extra (uv sync is exact) — keeps the gate offline-capable and fast — run `make ner-model` again after `make check` to restore spaCy in the dev venv.
