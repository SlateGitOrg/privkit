#!/usr/bin/env bash
# Offline end-to-end demo on the bundled synthetic fixtures. Run with `make demo`.
set -euo pipefail
cd "$(dirname "$0")/.."

FIX=examples/fixtures
OUT=out/demo
mkdir -p "$OUT"
rm -f "$OUT"/*
# DEMO-ONLY key (bytes 00..1f). Generate real keys with `privkit keygen` and keep them in a secret store.
export PRIVKIT_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
PK="uv run --quiet privkit"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
run() { printf '$ privkit %s\n' "$*"; $PK "$@"; }

step "1. Detect PII in support tickets (values hidden by default)"
run scan "$FIX/support_tickets.txt" | tail -n 8

step "2. Reversible tokenization of free text, then exact round trip"
run redact "$FIX/support_tickets.txt" --mode tokenize --tagged -o "$OUT/tickets.tokenized.txt"
sed -n '2p' "$OUT/tickets.tokenized.txt"
run detokenize "$OUT/tickets.tokenized.txt" -o "$OUT/tickets.restored.txt"
cmp -s "$FIX/support_tickets.txt" "$OUT/tickets.restored.txt" && echo "round trip: restored text is byte-identical"

step "3. Irreversible masking for logs"
run redact "$FIX/support_tickets.txt" --mode mask | sed -n '2p'

step "4. Find PII columns in a table"
run scan-table "$FIX/customers.csv" --sample 500

step "5. Format-preserving tokenization of columns (FF1, per-column keys)"
run tokenize-table "$FIX/customers.csv" --columns card_number=CREDIT_CARD,ssn=US_SSN,email=EMAIL,phone=PHONE -o "$OUT/customers.tokenized.csv"
echo "original : $(sed -n '2p' "$FIX/customers.csv")"
echo "tokenized: $(sed -n '2p' "$OUT/customers.tokenized.csv")"
run tokenize-table "$OUT/customers.tokenized.csv" --columns card_number=CREDIT_CARD,ssn=US_SSN,email=EMAIL,phone=PHONE --reverse -o "$OUT/customers.restored.csv"
cmp -s "$FIX/customers.csv" "$OUT/customers.restored.csv" && echo "round trip: 2000 rows restored byte-identically"

step "6. NIST SP 800-38G FF1 sample #1 (key 2B7E...4F3C, radix 10, empty tweak)"
NIST_KEY=2B7E151628AED2A6ABF7158809CF4F3C $PK fpe encrypt 0123456789 --key-env NIST_KEY | sed 's/^/ciphertext: /'
echo "expected  : 2433477484"

step "7. k-anonymity of the customer table over (age, zip, sex)"
run kanon "$FIX/customers.csv" --qi age,zip,sex --sensitive diagnosis -k 5
step "7b. Full-domain generalization to k=5 (<=2% suppression)"
run kanon "$FIX/customers.csv" --qi age,zip,sex --sensitive diagnosis -k 5 \
  --generalize age=interval:5,10,20 --generalize zip=mask:3 --max-suppression 0.02 -o "$OUT/customers.k5.csv"
step "7c. Mondrian to k=5"
run kanon "$FIX/customers.csv" --qi age,zip,sex -k 5 --mondrian --categorical zip -o "$OUT/customers.mondrian.csv"

step "8. Differentially private aggregates under a shared budget (eps=1.0, delta=1e-5, RDP)"
run budget init "$OUT/ledger.json" --epsilon 1.0 --delta 1e-5 --composition rdp
# --insecure-seed only makes this demo reproducible; never use it for real releases.
run dp "$FIX/transactions.csv" --metric count --privacy-unit user_id --group-by region \
  --epsilon 0.3 --delta 1e-6 --max-partitions 2 --ledger "$OUT/ledger.json" --label users_per_region --insecure-seed 7
run dp "$FIX/transactions.csv" --metric mean --privacy-unit user_id --group-by region --value amount \
  --lower 0 --upper 200 --max-partitions 2 --max-contributions 3 --epsilon 0.4 \
  --public-partitions north,south,east,west --ledger "$OUT/ledger.json" --label mean_amount --insecure-seed 8
step "8b. A query that would overspend the budget is refused (exit code 4)"
set +e
$PK dp "$FIX/transactions.csv" --metric sum --privacy-unit user_id --value amount --lower 0 --upper 200 \
  --epsilon 0.5 --ledger "$OUT/ledger.json" --insecure-seed 9
echo "exit code: $?"
set -e
run budget show "$OUT/ledger.json"

step "9. Detector precision/recall on the held-out synthetic split"
run eval --split test --docs 1000 --seed 2026
