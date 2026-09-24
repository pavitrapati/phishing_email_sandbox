"""Simulated internet for the detonation network.

Answers every DNS query with our own address, then accepts whatever the sample tries to
say to us and writes it down. Nothing here ever reaches the real internet -- the network
this runs on is `internal: true`, so there is no route off the host to begin with. This
service exists to make the sample *reveal* its C2 rather than to let it reach it.

Every observation is appended to NET_LOG as one JSON object per line:
    {"ts", "src", "kind", ...kind-specific fields}
The API filters those by worker IP and job time window.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SINK_IP = os.environ.get("SINK_IP", "127.0.0.1")
NET_LOG = os.environ.get("NET_LOG", "/net/events.jsonl")
MAX_BODY = 256 * 1024

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [fakenet] %(message)s",
)
log = logging.getLogger("fakenet")

_log_lock = threading.Lock()


def record(kind: str, src: str, **fields) -> None:
    """Append one observation. Never raise -- a logging failure must not kill a sink."""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src": src,
        "kind": kind,
        **fields,
    }
    try:
        with _log_lock:
            with open(NET_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
                fh.flush()
    except Exception:  # pragma: no cover - defensive
        log.exception("failed to record event")
    log.info("%s from %s: %s", kind, src, {k: v for k, v in fields.items() if k != "body"})


# --------------------------------------------------------------------------- DNS

_QTYPE = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS"}


def _parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated qname")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer -- not expected in a question
            offset += 2
            break
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), offset


def _build_response(query: bytes, qname_end: int, qtype: int) -> bytes:
    """Minimal DNS answer: A points at us, everything else gets NOERROR with no answer."""
    txid = query[:2]
    question = query[12:qname_end]

    if qtype == 1:  # A -- the only record type we actually answer
        rdata = socket.inet_aton(SINK_IP)
        ancount = 1
    else:
        # NOERROR with no answer. For AAAA this makes the client fall back to A;
        # there is no IPv6 on the detonation network, so a v6 answer would only stall it.
        rdata = b""
        ancount = 0

    header = txid + struct.pack(">HHHHH", 0x8180, 1, ancount, 0, 0)
    body = question
    if ancount:
        body += (
            b"\xc0\x0c"                              # pointer to the question name
            + struct.pack(">HHIH", qtype, 1, 60, len(rdata))
            + rdata
        )
    return header + body


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        src = self.client_address[0]
        try:
            qname, end = _parse_qname(data, 12)
            qtype = struct.unpack(">H", data[end : end + 2])[0]
            record("dns", src, qname=qname, qtype=_QTYPE.get(qtype, str(qtype)), answer=SINK_IP)
            sock.sendto(_build_response(data, end + 4, qtype), self.client_address)
        except Exception as exc:
            record("dns_error", src, error=str(exc))


class ThreadedUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


# -------------------------------------------------------------------------- HTTP


class SinkHTTPHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence the stdlib access log
        pass

    def _capture(self, method: str) -> None:
        src = self.client_address[0]
        try:
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        record(
            "http",
            src,
            method=method,
            host=self.headers.get("Host", ""),
            path=self.path,
            scheme="https" if getattr(self.server, "is_tls", False) else "http",
            user_agent=self.headers.get("User-Agent", ""),
            headers={k: v for k, v in self.headers.items()},
            body_len=length,
            body_preview=body[:2048].decode("utf-8", "replace"),
        )
        # A plausible-looking response keeps multi-stage droppers talking.
        payload = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._capture("GET")

    def do_POST(self):
        self._capture("POST")

    def do_HEAD(self):
        self._capture("HEAD")

    def do_PUT(self):
        self._capture("PUT")

    def do_OPTIONS(self):
        self._capture("OPTIONS")

    def do_CONNECT(self):
        record("http_connect", self.client_address[0], target=self.path)
        self.send_response(200, "Connection Established")
        self.end_headers()


def _self_signed_cert() -> tuple[str, str]:
    """Generate a throwaway cert. Samples never validate it; we only need TLS to complete."""
    tmp = tempfile.mkdtemp(prefix="fakenet-tls-")
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "3650",
         "-subj", "/CN=*.local/O=Sandbox"],
        check=True, capture_output=True,
    )
    return cert, key


def serve_http(port: int, tls: bool = False) -> None:
    httpd = ThreadingHTTPServer(("0.0.0.0", port), SinkHTTPHandler)
    httpd.daemon_threads = True
    httpd.is_tls = tls
    if tls:
        cert, key = _self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log.info("%s sink listening on :%d", "https" if tls else "http", port)
    httpd.serve_forever()


# --------------------------------------------------------------------- raw TCP


class RawSinkHandler(socketserver.BaseRequestHandler):
    """Catch-all for non-HTTP ports. Read whatever is sent, log it, stay quiet."""

    def handle(self) -> None:
        src = self.client_address[0]
        port = self.server.server_address[1]
        self.request.settimeout(5)
        chunks: list[bytes] = []
        total = 0
        try:
            while total < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except (socket.timeout, OSError):
            pass
        data = b"".join(chunks)
        record(
            "tcp",
            src,
            dport=port,
            bytes=len(data),
            preview=data[:512].decode("utf-8", "replace"),
        )


class ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_raw(port: int) -> None:
    try:
        ThreadedTCPServer(("0.0.0.0", port), RawSinkHandler).serve_forever()
    except OSError as exc:
        log.warning("raw sink :%d unavailable: %s", port, exc)


HTTP_PORTS = [80, 8080, 8000, 8888]
TLS_PORTS = [443, 8443]
# Ports malware reaches for that are not HTTP: mail exfil, IRC/C2, SMB, RDP, proxies.
RAW_PORTS = [21, 22, 23, 25, 110, 143, 445, 465, 587, 993, 995,
             1080, 1337, 3389, 4444, 5555, 6667, 9001, 9050]


def main() -> None:
    os.makedirs(os.path.dirname(NET_LOG), exist_ok=True)
    threads: list[threading.Thread] = []

    dns = ThreadedUDPServer(("0.0.0.0", 53), DNSHandler)
    threads.append(threading.Thread(target=dns.serve_forever, daemon=True, name="dns"))
    log.info("dns sink listening on :53, answering everything with %s", SINK_IP)

    for p in HTTP_PORTS:
        threads.append(threading.Thread(target=serve_http, args=(p, False), daemon=True, name=f"http{p}"))
    for p in TLS_PORTS:
        threads.append(threading.Thread(target=serve_http, args=(p, True), daemon=True, name=f"https{p}"))
    for p in RAW_PORTS:
        threads.append(threading.Thread(target=serve_raw, args=(p,), daemon=True, name=f"tcp{p}"))

    for t in threads:
        t.start()
    log.info("fakenet up: %d sinks", len(threads))

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
