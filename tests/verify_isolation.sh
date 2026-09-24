#!/usr/bin/env bash
# Verifies the containment claims in docs/ARCHITECTURE.md are actually true.
# Every check here is a claim the README makes; if one fails, the README is wrong.
set -uo pipefail

NET=sbx_detonation
IMAGE=sbx-worker:latest
pass=0; fail=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $name"; pass=$((pass+1))
  else
    echo "  FAIL  $name"; fail=$((fail+1))
  fi
}
check_fails() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL  $name (the operation succeeded when it must not)"; fail=$((fail+1))
  else
    echo "  PASS  $name"; pass=$((pass+1))
  fi
}

run_in_worker() {
  docker run --rm --network "$NET" --user 1000:1000 \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /tmp:rw,nosuid,size=64m \
    --entrypoint python "$IMAGE" -c "$1"
}

echo "Isolation checks against network '$NET':"

echo
echo "[1] The detonation network must have no route to the internet"
check_fails "raw TCP to 1.1.1.1:53 is blackholed" \
  run_in_worker 'import socket;socket.create_connection(("1.1.1.1",53),4)'
check_fails "raw TCP to 8.8.8.8:443 is blackholed" \
  run_in_worker 'import socket;socket.create_connection(("8.8.8.8",443),4)'
check_fails "HTTP to a real host fails" \
  run_in_worker 'import urllib.request;urllib.request.urlopen("http://example.com",timeout=4)'

echo
echo "[2] The network is marked internal in Docker's own view"
check "docker reports $NET as internal" \
  bash -c "docker network inspect $NET --format '{{.Internal}}' | grep -qx true"

echo
echo "[3] DNS must resolve to the fakenet sink, not to the real answer"
FAKENET_IP=$(docker inspect sbx-fakenet \
  --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" 2>/dev/null || echo "")
if [ -z "$FAKENET_IP" ]; then
  echo "  SKIP  fakenet is not running (start the stack with 'make up')"
else
  RESOLVED=$(docker run --rm --network "$NET" --dns "$FAKENET_IP" \
    --entrypoint python "$IMAGE" -c \
    'import socket;print(socket.gethostbyname("definitely-not-real-c2.example"))' 2>/dev/null || echo "")
  if [ "$RESOLVED" = "$FAKENET_IP" ]; then
    echo "  PASS  arbitrary domain resolves to the sink ($RESOLVED)"; pass=$((pass+1))
  else
    echo "  FAIL  expected $FAKENET_IP, got '${RESOLVED:-<nothing>}'"; fail=$((fail+1))
  fi
fi

echo
echo "[4] The worker must not be able to escalate or write to its own tooling"
check_fails "cannot write to /opt/worker" \
  run_in_worker 'open("/opt/worker/x","w")'
check_fails "cannot write to the read-only rootfs" \
  run_in_worker 'open("/etc/x","w")'
check "runs as uid 1000, not root" \
  bash -c "docker run --rm --network none --user 1000:1000 --entrypoint python $IMAGE -c 'import os;assert os.getuid()==1000'"
check_fails "cannot re-acquire privileges via a setuid binary" \
  docker run --rm --network none --user 1000:1000 --cap-drop ALL \
    --security-opt no-new-privileges:true --entrypoint python "$IMAGE" \
    -c 'import os;os.setuid(0)'

echo
echo "-------------------------------------------"
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
