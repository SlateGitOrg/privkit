# Threat model

privkit is a library and CLI that runs inside a data pipeline the operator controls. This
document lists what each control protects, against whom, and what it leaves open. It is
written for engineers deciding whether a privkit control is enough for a given data flow.

## System and trust boundaries

```
  trusted zone (raw PII, master key)            |  less-trusted zone (analytics, logs,
                                                |  vendors, test environments, public)
  source data ──► privkit scan / redact /       |
                  tokenize-table / kanon / dp ──┼──► tokenized or anonymized tables
                                                |    redacted text and logs
  PRIVKIT_KEY (env / secret store)              |    DP aggregates
  privacy ledger (JSON)                         |
```

* **Trusted:** the host running privkit, its environment variables (master key), the input
  files, and the ledger file.
* **Untrusted:** anyone who receives privkit's *outputs*. That includes analysts, vendors,
  log readers, and the public in the case of DP releases.

## Assets

| asset | why it matters |
|---|---|
| Raw identifiers (PAN, SSN, email, ...) | direct identification, fraud, regulatory exposure |
| Master key | anyone holding it can detokenize every token ever issued |
| Quasi-identifiers (age, ZIP, sex, ...) | linkage attacks re-identify "anonymous" rows (Sweeney 2002) |
| Individual contributions to aggregates | membership and attribute inference from published statistics |
| Privacy ledger | an attacker who resets it could overspend the budget |

## Adversaries and controls

### A1. Recipient of tokenized data, without the key

* **Control:** FF1 / FF3-1 tokens under per-policy HKDF-derived AES-256 keys.
* **Protects against:** recovering values from tokens, and correlating tokens across policies
  or columns, since each uses a different key.
* **Does not protect against:**
  * **Equality and frequency analysis.** Tokens are deterministic. Equal values give equal
    tokens, so a column with few distinct values (gender, state) leaks its histogram, and
    rare values stay rare.
  * **Kept characters.** The CREDIT_CARD policy shows the last 4 digits and EMAIL shows the
    domain, by design.
  * **Small plaintext spaces.** Domains under 10⁶ are refused, but a large *cipher* domain
    does not add entropy to the *plaintext*. An attacker with an encryption oracle (someone
    who can submit values for tokenization) can enumerate a low-entropy field such as a date
    of birth.
* **Residual:** tokenized data is **pseudonymous, not anonymous** (GDPR Recital 26). Treat it
  as personal data.

### A2. Holder of the master key

* Can detokenize everything. privkit has no key management, rotation or HSM support. Keys
  come from an environment variable, and protecting them is the operator's job (secret
  manager, least privilege, audit). This repository and its demo use a fixed, publicly known
  *demo* key that must never be used for real data.

### A3. Reader of redacted or masked text and logs

* **Control:** the detector plus Redact / Mask / Pseudonymize.
* **Protects against:** reading the identifiers the detector finds.
* **Does not protect against:** PII the detector misses. Coverage is pattern-based (see
  README Limitations): names without NER, addresses, free-form IDs, and PII split across
  lines, obfuscated or inside images all get through. Masking with `keep_last` deliberately
  leaks a suffix. Pseudonyms (keyed HMAC) can be linked across documents under one key.
* **Defence in depth inside privkit:** `Finding.__repr__` hides values, error messages never
  include values, and loggers emit only entity types and counts. A unit test asserts that a
  detected SSN does not appear in captured DEBUG logs.

### A4. Linkage attacker against a released table (k-anonymity)

* **Control:** `assess` measures k, l-diversity, t-closeness and prosecutor risk.
  `generalize_to_k` and `mondrian` enforce k over the QIs the operator lists.
* **Does not protect against:**
  * QIs the operator did not list. The guarantee is only as good as the QI selection.
  * Homogeneity and background-knowledge attacks when l-diversity is low. The report shows
    distinct-l and entropy-l but does not enforce them.
  * Composition across releases. Two k-anonymous releases of overlapping data can be
    intersected.
  * k-anonymity is a *syntactic* property with no formal guarantee against an adversary with
    auxiliary data. Use DP when that matters.

### A5. Consumer of DP aggregates (including the public)

* **Control:** calibrated noise with bounded contributions and a budget accountant. See
  [DP_GUARANTEES.md](DP_GUARANTEES.md) for exactly what is and is not guaranteed.
* **Implementation-level threats:**
  * **Floating-point attacks** (Mironov 2012) on continuous Laplace sampling. Integer queries
    use exact discrete samplers that avoid this. Real-valued sums and means still use
    floating-point continuous noise. This is documented as a limitation.
  * **Predictable randomness.** The default RNG is `secrets.SystemRandom` (the OS CSPRNG).
    The seeded RNG behind `--insecure-seed` logs a warning on every use and must never be
    used for real releases.
  * **Timing side channels.** Rejection samplers run in data-independent expected time, but
    timing is not hardened. Do not expose privkit as a low-latency query service to
    untrusted callers.
  * **Ledger tampering.** The ledger is a plain JSON file. Deleting or editing it resets the
    budget. Protect it like the data, and do not share one ledger between concurrent
    processes: the lock is per process.

## Explicit non-goals

* Protecting data *inside* the trusted zone, for example from a compromised host.
* Encryption at rest or in transit (use the platform's TLS, KMS and disk encryption).
* Access control, consent management, retention, or deletion workflows.
* Detecting PII in binary formats (images, PDFs, audio).

## Ethics and scope

privkit is a defensive, educational toolkit. All bundled data is synthetic and every demo
runs offline on local fixtures. Nothing in the repository targets real systems or people.
