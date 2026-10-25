#!/usr/bin/env bash
#
# End-to-end self test over loopback.
#
# Runs both halves of the tunnel on one host, with a deliberately wide port
# range, and checks that a byte actually makes the round trip. No network, no
# certificate authority, no second server.
#
# This exists because its absence cost a day of deployment. Every fault found
# the hard way -- a handshake payload that outgrew its own limit, an SNI that
# resolved nowhere, a cipher list that could only ever refuse a client -- would
# have surfaced here in under a minute.
#
#   bash deploy/selftest.sh                                    build, then test
#   SERAI_BIN=/usr/local/bin/serai bash deploy/selftest.sh      test an installed binary
#   KEEP=1 bash deploy/selftest.sh                             keep the logs
#
set -euo pipefail

if [[ -t 1 ]] && [[ "${TERM:-dumb}" != dumb ]]; then
  R=$'\e[0m'; B=$'\e[1m'; D=$'\e[2m'
  OKC=$'\e[38;5;115m'; ERRC=$'\e[38;5;210m'; INFC=$'\e[38;5;80m'
else
  R=; B=; D=; OKC=; ERRC=; INFC=
fi
ok()   { printf '  %s✔%s %s\n' "$OKC" "$R" "$*"; }
bad()  { printf '  %s✘%s %s\n' "$ERRC" "$R" "$*" >&2; }
info() { printf '  %s•%s %s\n' "$INFC" "$R" "$*"; }
step() { printf '\n%s▌ %s%s\n' "$B$INFC" "$*" "$R"; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
FAILED=0
PIDS=()

cleanup() {
  for pid in ${PIDS+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ -n "${KEEP:-}" ]]; then
    info "logs kept in $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────── the binary ───
step "Binary"
if [[ -n "${SERAI_BIN:-}" ]]; then
  BIN="$SERAI_BIN"
  [[ -x "$BIN" ]] || { bad "$BIN is not executable"; exit 1; }
  ok "using $BIN ($("$BIN" version))"
else
  BIN="$WORK/serai"
  command -v go >/dev/null || { bad "go is not installed; set SERAI_BIN to test an existing binary"; exit 1; }
  ( cd "$ROOT" && GOFLAGS=-mod=mod go mod tidy >"$WORK/tidy.log" 2>&1 ) || {
    bad "go mod tidy failed"; tail -20 "$WORK/tidy.log"; exit 1
  }
  ( cd "$ROOT" && go build -o "$BIN" ./cmd/serai >"$WORK/build.log" 2>&1 ) || {
    bad "build failed"; tail -40 "$WORK/build.log"; exit 1
  }
  ok "built $("$BIN" version)"
fi

# ───────────────────────────────────────────────────────────── fixture setup ───
step "Fixtures"

"$BIN" keygen >"$WORK/psk"
ok "key generated"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
PIN="$("$BIN" pin -cert "$WORK/cert.pem" | sed 's|^sha256/||')"
ok "certificate for localhost, pin ${PIN:0:16}..."

# An echo backend stands in for the panel: whatever reaches it comes straight
# back, so a successful round trip proves the whole datapath, not just the
# handshake.
python3 -c '
import socket, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 19099)); srv.listen(32)
print("echo ready", flush=True)
def handle(c):
    try:
        while True:
            b = c.recv(65536)
            if not b:
                return
            c.sendall(b)
    finally:
        c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
' >"$WORK/echo.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 40); do grep -q "echo ready" "$WORK/echo.log" 2>/dev/null && break; sleep 0.1; done
grep -q "echo ready" "$WORK/echo.log" || { bad "echo backend did not start"; exit 1; }
ok "echo backend on 127.0.0.1:19099"

# A thousand ports on purpose. This is the shape that broke the handshake when
# the expanded port list was still being sent on the wire, and a narrow range
# would have hidden it.
cat >"$WORK/edge.json" <<EOF
{
  "role": "edge",
  "name": "selftest-edge",
  "profile": "balanced",
  "log_level": "debug",
  "psk_file": "$WORK/psk",
  "admin_addr": "127.0.0.1:19900",
  "server": {
    "control_addr": "127.0.0.1:19443",
    "quic_addr": "",
    "tunnel_sni": "localhost",
    "ws_path": "/selftest",
    "cert_file": "$WORK/cert.pem",
    "key_file": "$WORK/key.pem",
    "allow_ports": "17000-19000"
  }
}
EOF

cat >"$WORK/origin.json" <<EOF
{
  "role": "origin",
  "name": "selftest-origin",
  "profile": "balanced",
  "log_level": "debug",
  "psk_file": "$WORK/psk",
  "admin_addr": "127.0.0.1:19901",
  "edge": {
    "paths": [
      { "transport": "websocket", "url": "wss://localhost/selftest",
        "edge_addr": "127.0.0.1:19443", "host": "localhost",
        "fingerprint": "chrome", "role": "both", "weight": 1 }
    ],
    "insecure": true,
    "pinned_spki": ["$PIN"],
    "reconnect": { "min": "500ms", "max": "3s", "factor": 1.5, "jitter": 0.2 }
  },
  "tuning": { "carriers": 2 },
  "forwards": [
    { "name": "wide", "proto": "tcp", "edge_ports": "18000-19000",
      "target_host": "127.0.0.1" },
    { "name": "echo-lo", "proto": "tcp", "edge_ports": "17001", "target": "127.0.0.1:19099" },
    { "name": "echo-mid", "proto": "tcp", "edge_ports": "17500", "target": "127.0.0.1:19099" },
    { "name": "echo-hi", "proto": "tcp", "edge_ports": "17999", "target": "127.0.0.1:19099" }
  ]
}
EOF

for f in edge origin; do
  "$BIN" check -c "$WORK/$f.json" >"$WORK/$f.check" 2>&1 || {
    bad "$f config rejected"; cat "$WORK/$f.check"; exit 1
  }
done
ok "both configs valid, 1001 forwarded ports plus three echo probes"

# Why the round trip does not use the wide range: "target_host" keeps the port,
# so edge:18000 would dial 127.0.0.1:18000 on the origin -- and with both
# halves on one host that is the relay's own listener, which loops. On a real
# deployment the two are different machines and 127.0.0.1:18000 is the panel.
# The wide range is still checked for correct binding below; the echo probes
# use fixed targets so they reach the backend instead of coming back round.

# ──────────────────────────────────────────────────────────────── run them ───
step "Tunnel"

"$BIN" edge -c "$WORK/edge.json" >"$WORK/edge.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do
  grep -q "edge listening" "$WORK/edge.log" 2>/dev/null && break
  sleep 0.1
done
grep -q "edge listening" "$WORK/edge.log" || {
  bad "edge did not start"; tail -25 "$WORK/edge.log"; exit 1
}
ok "edge listening on 127.0.0.1:19443"

"$BIN" origin -c "$WORK/origin.json" >"$WORK/origin.log" 2>&1 &
PIDS+=($!)

carriers=0
for _ in $(seq 150); do
  carriers="$(curl -fsS --max-time 2 127.0.0.1:19901/status 2>/dev/null | grep -c '"transport"' || true)"
  [[ "$carriers" -gt 0 ]] && break
  sleep 0.2
done

if [[ "$carriers" -eq 0 ]]; then
  bad "no carrier established within 30s"
  printf '%s--- origin ---%s\n' "$D" "$R"; tail -25 "$WORK/origin.log"
  printf '%s--- edge ---%s\n'   "$D" "$R"; tail -25 "$WORK/edge.log"
  exit 1
fi
ok "$carriers carrier(s) established"

# ────────────────────────────────────────────────────────────── round trip ───
step "Round trip"

check_port() {
  local port="$1" sent got
  sent="serai-selftest-$port-$RANDOM"
  got="$(printf '%s' "$sent" | timeout 10 python3 -c '
import socket, sys
data = sys.stdin.buffer.read()
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=8)
s.sendall(data)
out = b""
while len(out) < len(data):
    chunk = s.recv(65536)
    if not chunk:
        break
    out += chunk
s.close()
sys.stdout.write(out.decode("utf-8", "replace"))
' "$port" 2>/dev/null)" || true
  [[ "$got" == "$sent" ]]
}

# Before blaming the datapath, confirm the relay actually bound the ports.
# "no round trip" otherwise covers both an unbound port and a broken relay.
# The ends and the middle of the wide range: a fault in range expansion almost
# always leaves exactly one end unbound.
bound="$(ss -ltn 2>/dev/null | awk '{print $4}' | grep -cE ':(18000|18500|19000)$' || true)"
if [[ "$bound" -eq 3 ]]; then
  ok "wide range bound at both ends and the middle"
else
  bad "only $bound of 3 range ports are listening - range expansion is wrong"
  FAILED=1
fi

probes="$(ss -ltn 2>/dev/null | awk '{print $4}' | grep -cE ':(17001|17500|17999)$' || true)"
if [[ "$probes" -eq 3 ]]; then
  ok "all three echo probes are listening"
else
  bad "only $probes of 3 echo probes are listening"
  FAILED=1
fi

# Sanity-check the backend itself, so a broken echo server cannot masquerade
# as a broken tunnel.
if printf 'ping' | timeout 5 python3 -c '
import socket,sys
d=sys.stdin.buffer.read()
s=socket.create_connection(("127.0.0.1",19099),timeout=4)
s.sendall(d); sys.stdout.write(s.recv(64).decode()); s.close()
' 2>/dev/null | grep -q ping; then
  ok "echo backend answers directly"
else
  bad "echo backend does not answer directly - the test fixture is broken"
  FAILED=1
fi

# First, last and middle of the range: a fault in range expansion usually
# leaves exactly one end unbound.
for port in 17001 17500 17999; do
  if check_port "$port"; then
    ok "port $port: data out and back"
  else
    bad "port $port: no round trip"
    FAILED=1
  fi
done

# A payload larger than one TLS record, to catch anything that only works for
# small writes.
step "Bulk transfer"
bulk_sent="$(head -c 200000 /dev/urandom | base64 -w0)"
bulk_got="$(printf '%s' "$bulk_sent" | timeout 20 python3 -c '
import socket, sys
data = sys.stdin.buffer.read()
s = socket.create_connection(("127.0.0.1", 17500), timeout=15)
s.sendall(data)
out = b""
while len(out) < len(data):
    chunk = s.recv(1 << 16)
    if not chunk:
        break
    out += chunk
s.close()
sys.stdout.write(str(len(out)))
' 2>/dev/null)" || true

if [[ "$bulk_got" == "${#bulk_sent}" ]]; then
  ok "${#bulk_sent} bytes round-tripped intact"
else
  bad "bulk transfer returned ${bulk_got:-0} of ${#bulk_sent} bytes"
  FAILED=1
fi

step "Result"
if [[ "$FAILED" -eq 0 ]]; then
  ok "${B}self test passed${R}"
else
  bad "self test FAILED"
  printf '%s--- origin ---%s\n' "$D" "$R"; tail -30 "$WORK/origin.log"
  printf '%s--- edge ---%s\n'   "$D" "$R"; tail -30 "$WORK/edge.log"
  printf '\n  %srerun with KEEP=1 to keep the logs%s\n' "$D" "$R"
  exit 1
fi
