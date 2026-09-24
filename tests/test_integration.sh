#!/usr/bin/env bash
# Detonates every sample against the running stack and asserts the verdicts.
#
# Expectations are written as MINIMUM severity, not exact scores. Scores shift whenever a
# rule is tuned; what must not shift is that a hostile sample never comes back benign and
# a benign sample never comes back malicious. Asserting exact numbers would make this
# suite fail for the wrong reasons.
set -o pipefail

API="${SANDBOX_API:-http://127.0.0.1:8090}"
KEY="${API_KEY:-}"
SAMPLES="$(cd "$(dirname "$0")" && pwd)/samples"
OUT="${OUT_DIR:-/tmp/sbx-integration}"
mkdir -p "$OUT"

pass=0; fail=0
declare -a FAILED

hdr=()
[ -n "$KEY" ] && hdr=(-H "X-API-Key: $KEY")

jqv() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1],{'d':d,'json':json}))" "$1"; }

echo "Checking the API is up at $API ..."
if ! curl -fsS "${hdr[@]}" "$API/healthz" >/dev/null 2>&1; then
  echo "FATAL: API is not reachable at $API. Run 'make up' first." >&2
  exit 2
fi
health=$(curl -fsS "${hdr[@]}" "$API/healthz")
echo "  health: $health"
echo

# sample | minimum level | signature that must be present (empty = none required)
CASES=(
  "benign_report.pdf|benign|"
  "meeting_notes.txt|benign|"
  "invoice_scan.pdf|malicious|PDF_LAUNCH_ACTION"
  "payment_advice.docx|malicious|OFFICE_REMOTE_TEMPLATE"
  "invoice_2024.doc|malicious|OFFICE_MACRO_AUTOEXEC"
  "shipping_documents.zip|suspicious|ARCHIVE_DANGEROUS_CONTENT"
  "invoice_details.js|suspicious|SCRIPT_OBFUSCATED"
  "update_helper.sh|suspicious|DYN_PROCESS_SPAWN"
  "SecurityUpdate.scr|suspicious|PE_PACKED"
)

level_rank() {
  case "$1" in benign) echo 0;; suspicious) echo 1;; malicious) echo 2;; *) echo -1;; esac
}

for case_line in "${CASES[@]}"; do
  IFS='|' read -r name expect_level expect_sig <<< "$case_line"
  path="$SAMPLES/$name"
  [ -f "$path" ] || { echo "  SKIP  $name (missing; run 'make samples')"; continue; }

  printf '  %-28s ' "$name"
  body=$(curl -fsS "${hdr[@]}" -F "file=@$path" "$API/v1/analyze/sync" 2>/dev/null)
  if [ -z "$body" ]; then
    echo "FAIL  (no response from the API)"; fail=$((fail+1)); FAILED+=("$name: no response"); continue
  fi
  echo "$body" > "$OUT/${name}.json"

  status=$(echo "$body" | jqv "d['status']")
  level=$(echo "$body"  | jqv "d['verdict']['level']")
  score=$(echo "$body"  | jqv "d['verdict']['score']")
  sigs=$(echo "$body"   | jqv "','.join(s['id'] for s in d['signatures'])")

  problems=""
  [ "$status" = "completed" ] || problems="$problems status=$status;"

  got=$(level_rank "$level"); want=$(level_rank "$expect_level")
  if [ "$expect_level" = "benign" ]; then
    [ "$got" -le 1 ] || problems="$problems expected at most suspicious, got $level;"
  else
    [ "$got" -ge "$want" ] || problems="$problems expected >= $expect_level, got $level;"
  fi

  if [ -n "$expect_sig" ] && [[ ",$sigs," != *",$expect_sig,"* ]]; then
    problems="$problems missing signature $expect_sig;"
  fi

  if [ -z "$problems" ]; then
    echo "OK    $level ($score/100)  [$(echo "$sigs" | tr ',' ' ' | wc -w) signatures]"
    pass=$((pass+1))
  else
    echo "FAIL  $level ($score/100) -- $problems"
    echo "        fired: $sigs"
    fail=$((fail+1)); FAILED+=("$name: $problems")
  fi
done

echo
echo "Checking the async submit/poll path ..."
job=$(curl -fsS "${hdr[@]}" -F "file=@$SAMPLES/meeting_notes.txt" "$API/v1/analyze" \
      | jqv "d['job_id']")
if [ -n "$job" ]; then
  for _ in $(seq 1 60); do
    resp=$(curl -fsS -o "$OUT/async.json" -w '%{http_code}' "${hdr[@]}" "$API/v1/report/$job")
    [ "$resp" = "200" ] && break
    sleep 2
  done
  if [ "$resp" = "200" ]; then
    echo "  PASS  async job $job completed"; pass=$((pass+1))
  else
    echo "  FAIL  async job $job never completed (last HTTP $resp)"; fail=$((fail+1))
    FAILED+=("async polling")
  fi
else
  echo "  FAIL  async submit returned no job id"; fail=$((fail+1)); FAILED+=("async submit")
fi

echo
echo "Checking the fakenet captured the shell dropper's traffic ..."
netcheck=$(python3 - "$OUT/update_helper.sh.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
net = d.get("network", {})
dns = [q.get("qname") for q in net.get("dns_queries", [])]
http = net.get("http_requests", [])
connects = net.get("connect_attempts", [])
hits = []
if any("c2.example.net" in (q or "") for q in dns):
    hits.append("dns")
if any("c2.example.net" in (r.get("host") or "") for r in http):
    hits.append("http")
if any(c.get("ip") == "192.0.2.66" for c in connects):
    hits.append("raw-ip-connect")
print(",".join(hits) if hits else "NONE")
PY
)
if [ "$netcheck" = "NONE" ]; then
  echo "  FAIL  no simulated-internet activity captured"; fail=$((fail+1))
  FAILED+=("fakenet capture")
else
  echo "  PASS  captured: $netcheck"; pass=$((pass+1))
fi

echo
echo "Checking every report is safe to hand to an LLM ..."
llmcheck=$(python3 - "$OUT" <<'PY'
import glob, json, os, sys, re
bad = []
for path in glob.glob(os.path.join(sys.argv[1], "*.json")):
    try:
        d = json.load(open(path))
    except Exception:
        continue
    s = d.get("llm_summary", "")
    if not s:
        continue
    if re.search(r"https?://", s):
        bad.append(f"{os.path.basename(path)}: live URL in llm_summary")
    if len(s) > 60000:
        bad.append(f"{os.path.basename(path)}: llm_summary is {len(s)} chars")
print("; ".join(bad) if bad else "OK")
PY
)
if [ "$llmcheck" = "OK" ]; then
  echo "  PASS  all summaries defanged and reasonably sized"; pass=$((pass+1))
else
  echo "  FAIL  $llmcheck"; fail=$((fail+1)); FAILED+=("llm_summary safety")
fi

echo
echo "Checking no worker containers were left behind ..."
leftover=$(docker ps -aq --filter "label=sbx.role=worker" | wc -l)
if [ "$leftover" -eq 0 ]; then
  echo "  PASS  no leftover worker containers"; pass=$((pass+1))
else
  echo "  FAIL  $leftover worker container(s) still present"; fail=$((fail+1))
  FAILED+=("container cleanup")
fi

echo
echo "==========================================="
echo "  $pass passed, $fail failed"
echo "  reports written to $OUT"
if [ ${#FAILED[@]} -gt 0 ]; then
  echo
  echo "Failures:"
  printf '  - %s\n' "${FAILED[@]}"
fi
[ "$fail" -eq 0 ] || exit 1
