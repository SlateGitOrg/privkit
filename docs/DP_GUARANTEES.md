# What differential privacy does and does not guarantee in privkit

## The guarantee, stated precisely

A randomized algorithm M is (ε, δ)-differentially private if, for every pair of datasets D
and D′ that differ in **all records of one privacy unit**, and every set of outputs S,

    P[M(D) ∈ S] ≤ e^ε · P[M(D′) ∈ S] + δ.

In privkit the *privacy unit* is the column you pass as `--privacy-unit` (`privacy_unit`
in the library), usually a user id. Contribution bounding is what turns record-level noise
into a unit-level guarantee: every unit is cut down to at most L0 partitions and L∞ records
per partition, and the noise is calibrated to that bound.

Informally, an observer of the output learns about the same about any single unit whether
or not that unit's data was included. The likelihood ratio is at most e^ε, except with
probability δ.

## What privkit's DP releases guarantee

1. **Unit-level privacy for every released number.** This assumes the privacy-unit column
   really identifies one person. If one person has several user ids, the guarantee degrades
   with the number of ids.
2. **Privacy of which group keys appear.** Without `public_partitions`, keys are released
   only via thresholded noisy counts of distinct units, so a key held by a single user is
   published with probability at most δ_sel/L0 per key.
3. **Composition across queries charged to one ledger.** The accountant refuses any release
   that would push the composed cost over budget, and it records nothing when it refuses.
4. **Post-processing immunity.** Rounding, clamping counts at zero, dividing a noisy sum by a
   noisy count and clamping means to the value range are all functions of DP outputs only,
   so they cannot weaken the guarantee.
5. **Exactness for integer queries.** Counts and integer sums are noised with exact discrete
   Laplace and discrete Gaussian samplers, which avoids the floating-point attacks on naive
   continuous samplers.

## What it does **not** guarantee

* **Accuracy.** Noise standard deviations and 95% half-widths are reported next to each
  value. Small groups can be dominated by noise; the demo's empty `north` partition comes
  back as 0 ± 916. DP trades accuracy for privacy by design.
* **Protection beyond the declared unit.** Household members, correlated records, or a
  person present under two ids are not covered by a user-level guarantee.
* **Protection when the bounds are wrong.** Values outside `[lower, upper]` are clamped.
  That keeps privacy intact but biases the result. Bounds must be chosen *without looking
  at the data*. Choosing them from the data itself leaks information that the budget does
  not account for.
* **Secrecy of population-level facts.** DP hides individuals, not trends. If the data shows
  that region X spends more, a DP mean will say so too.
* **Unlimited queries.** Each query spends budget. Once the budget is gone, further releases
  must be refused, and the accountant refuses them. Resetting or deleting the ledger file
  voids the guarantee.
* **Safety of non-DP outputs.** k-anonymized tables, tokenized tables and redacted text do
  not carry a DP guarantee. Publishing them next to DP aggregates composes badly.
* **Adaptive-parameter composition with advanced or RDP accounting.** The advanced
  composition theorem and the RDP conversion are valid when the sequence of mechanisms and
  their parameters is fixed in advance, or at least not chosen from earlier noisy answers.
  For fully adaptive budgeting, where each ε is chosen after seeing earlier outputs, use
  `composition="basic"`. Summing ε as a budget filter remains valid in that setting
  (Rogers et al. 2016). RDP privacy filters (Feldman & Zrnic 2021) are on the roadmap.
* **Floating-point exactness for real-valued sums and means.** These use the continuous
  Laplace or Gaussian mechanism in IEEE-754 doubles. Their theoretical guarantee holds for
  ideal real arithmetic, and implementations are known to deviate (Mironov 2012). Prefer
  integer-valued bounds (for example amounts in cents) so the exact discrete samplers are
  used.
* **Seeded runs.** `--insecure-seed` and `insecure_seeded_rng` make noise reproducible and
  therefore provide **no** privacy. They exist only for tests and demos.

## Choosing parameters

* ε is the main dial. Published deployments range from ε < 1 (strong) to single digits per
  release. Pick ε per release *and* a total budget per dataset and time window.
* δ should be far below 1/n, the inverse of the number of units. 1e-6 to 1e-9 is typical.
  δ is needed for Gaussian noise and for private partition selection.
* L0 / L∞: smaller bounds mean less noise but drop more data from heavy contributors.
  Pick them from domain knowledge, for example "a user can live in at most 2 regions".

## Composition rules implemented

| rule | ε after k releases of ε₀ (pure) | valid for adaptive parameters |
|---|---|---|
| basic | k·ε₀ | yes |
| advanced (δ′ slack) | √(2k ln 1/δ′)·ε₀ + k·ε₀(e^ε₀ − 1) | no (fixed parameters) |
| RDP | min over α of Σ RDP(α) + conversion term | no (fixed parameters) |

The accountant always reports the smallest valid ε among basic and the selected rule. For
example, `tests/unit/test_dp_accountant.py` shows 200 Laplace releases at ε = 0.05 composing
to under 6.0 with advanced composition, against 10.0 with basic.
