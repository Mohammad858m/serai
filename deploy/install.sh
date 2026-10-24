#!/usr/bin/env bash
#
# Serai installer — reverse tunnel for panel-based proxies.
#
#   bash install.sh            interactive menu
#   bash install.sh edge       install the relay (the host users connect to)
#   bash install.sh origin     install the origin (the host running 3x-ui)
#   bash install.sh status     show what is running
#   bash install.sh uninstall  remove everything
#
set -euo pipefail

REPO_URL="${SERAI_REPO:-https://github.com/Mohammad858m/serai}"
PREFIX=/usr/local/bin
CONF_DIR=/etc/serai
STATE_DIR=/var/lib/serai
BIN="$PREFIX/serai"
GO_VERSION="1.23.4"

# ──────────────────────────────────────────────────────────────── palette ────
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != dumb ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_TEAL=$'\e[38;5;80m'; C_MINT=$'\e[38;5;115m'; C_AMBER=$'\e[38;5;215m'
  C_ROSE=$'\e[38;5;210m'; C_SLATE=$'\e[38;5;245m'; C_PLUM=$'\e[38;5;183m'
  C_BG=$'\e[48;5;236m'
else
  C_RESET=; C_BOLD=; C_DIM=; C_TEAL=; C_MINT=; C_AMBER=; C_ROSE=; C_SLATE=; C_PLUM=; C_BG=
fi

W=68
rule()  { printf '%s%s%s\n' "$C_SLATE" "$(printf '─%.0s' $(seq 1 $W))" "$C_RESET"; }
title() { printf '\n%s%s %s %s\n' "$C_BOLD$C_TEAL" "▌" "$*" "$C_RESET"; }
ok()    { printf '  %s✔%s %s\n' "$C_MINT" "$C_RESET" "$*"; }
info()  { printf '  %s•%s %s\n' "$C_TEAL" "$C_RESET" "$*"; }
warn()  { printf '  %s!%s %s\n' "$C_AMBER" "$C_RESET" "$*"; }
err()   { printf '  %s✘%s %s\n' "$C_ROSE" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }
kv()    { printf '  %s%-22s%s %s\n' "$C_SLATE" "$1" "$C_RESET" "$2"; }

banner() {
  printf '\n'
  printf '%s   ███████ ███████ ██████   █████  ██%s\n'  "$C_TEAL"  "$C_RESET"
  printf '%s   ██      ██      ██   ██ ██   ██ ██%s\n'  "$C_TEAL"  "$C_RESET"
  printf '%s   ███████ █████   ██████  ███████ ██%s\n'  "$C_MINT"  "$C_RESET"
  printf '%s        ██ ██      ██   ██ ██   ██ ██%s\n'  "$C_MINT"  "$C_RESET"
  printf '%s   ███████ ███████ ██   ██ ██   ██ ██%s\n'  "$C_PLUM"  "$C_RESET"
  printf '\n   %sa caravanserai for your traffic%s\n' "$C_DIM" "$C_RESET"
  printf '   %sreverse tunnel · multipath · browser-shaped TLS%s\n\n' "$C_SLATE" "$C_RESET"
}

spin() {
  # spin "message" command...
  local msg="$1"; shift
  local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' log; log="$(mktemp)"
  "$@" >"$log" 2>&1 &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$(((i + 1) % ${#frames}))
    printf '\r  %s%s%s %s' "$C_TEAL" "${frames:i:1}" "$C_RESET" "$msg"
    sleep 0.08
  done
  if wait "$pid"; then
    printf '\r  %s✔%s %s\n' "$C_MINT" "$C_RESET" "$msg"
    rm -f "$log"
  else
    printf '\r  %s✘%s %s\n' "$C_ROSE" "$C_RESET" "$msg"
    printf '%s' "$C_DIM"; tail -n 20 "$log"; printf '%s' "$C_RESET"
    rm -f "$log"
    return 1
  fi
}

ask() {
  # ask VAR "prompt" "default"
  local __var="$1" prompt="$2" default="${3:-}" reply
  if [[ -n "$default" ]]; then
    printf '  %s?%s %s %s[%s]%s ' "$C_AMBER" "$C_RESET" "$prompt" "$C_DIM" "$default" "$C_RESET"
  else
    printf '  %s?%s %s ' "$C_AMBER" "$C_RESET" "$prompt"
  fi
  read -r reply </dev/tty || true
  printf -v "$__var" '%s' "${reply:-$default}"
}

confirm() {
  local reply
  printf '  %s?%s %s %s[y/N]%s ' "$C_AMBER" "$C_RESET" "$1" "$C_DIM" "$C_RESET"
  read -r reply </dev/tty || true
  [[ "$reply" =~ ^[Yy] ]]
}

# ───────────────────────────────────────────────────────────── environment ────
need_root() { [[ $EUID -eq 0 ]] || die "run as root (try: sudo bash $0)"; }

detect_os() {
  [[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
  case "$OS_ID" in
    debian|ubuntu)             PKG=apt ;;
    centos|rhel|almalinux|rocky|fedora) PKG=dnf; command -v dnf >/dev/null || PKG=yum ;;
    *) PKG="" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
}

pkg_install() {
  [[ -n "$PKG" ]] || { warn "unknown package manager; install manually: $*"; return 0; }
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
  esac
}

ensure_deps() {
  local missing=()
  for c in curl tar git; do command -v "$c" >/dev/null || missing+=("$c"); done
  ((${#missing[@]})) && spin "installing ${missing[*]}" pkg_install "${missing[@]}"
  return 0
}

ensure_go() {
  if command -v go >/dev/null; then
    ok "go $(go version | awk '{print $3}') present"
    return
  fi
  if [[ -x /usr/local/go/bin/go ]]; then
    export PATH="/usr/local/go/bin:$PATH"
    ok "go found at /usr/local/go"
    return
  fi
  spin "downloading go ${GO_VERSION}" bash -c \
    "curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"
  spin "installing go toolchain" bash -c \
    "rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz"
  export PATH="/usr/local/go/bin:$PATH"
}

build_binary() {
  local src
  if [[ -f "$(dirname "$0")/../go.mod" ]]; then
    src="$(cd "$(dirname "$0")/.." && pwd)"
    info "building from local checkout at $src"
  else
    src="$(mktemp -d)"
    spin "fetching source" git clone --depth 1 "$REPO_URL" "$src"
  fi
  spin "building serai (static, stripped)" bash -c "
    cd '$src' &&
    GOFLAGS=-trimpath CGO_ENABLED=0 go build \
      -ldflags '-s -w -X main.version=\$(git -C \"$src\" describe --tags --always 2>/dev/null || echo dev)' \
      -o '$BIN' ./cmd/serai"
  chmod 0755 "$BIN"
  ok "installed $($BIN version)"
}

# ─────────────────────────────────────────────────────────── kernel tuning ────
tune_kernel() {
  title "Kernel tuning"
  cat >/etc/sysctl.d/99-serai.conf <<'SYSCTL'
# Serai: throughput and connection-rate tuning for a relay.

# BBR with fair queueing. On a long, slightly lossy path this is the single
# biggest throughput win available: CUBIC reads loss as congestion and
# collapses its window, while BBR paces to the measured bottleneck instead.
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Socket buffers large enough for a high bandwidth-delay product. A 200 ms
# path at 1 Gbit/s needs ~25 MB in flight; the defaults cap far below that.
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 262144 67108864
net.ipv4.tcp_wmem = 4096 262144 67108864
net.ipv4.tcp_adv_win_scale = -2

# Accept bursts of new connections instead of dropping SYNs.
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_syncookies = 1

# Recycle closed sockets quickly: a relay opens and closes a great many.
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10240 65000

# Keep idle tunnels alive through NAT without an application-level timer.
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 20
net.ipv4.tcp_keepalive_probes = 4

net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# UDP buffers, for QUIC and for Hysteria-style inbounds.
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# Forwarding and conntrack headroom.
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 262144
fs.file-max = 2097152
SYSCTL

  sysctl --system >/dev/null 2>&1 || warn "some sysctl keys were rejected by this kernel"

  local cc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  if [[ "$cc" == bbr ]]; then
    ok "congestion control: bbr + fq"
  else
    warn "congestion control is '$cc' — this kernel may lack the bbr module"
  fi

  mkdir -p /etc/security
  if ! grep -q '^# serai' /etc/security/limits.conf 2>/dev/null; then
    cat >>/etc/security/limits.conf <<'LIMITS'
# serai
* soft nofile 1048576
* hard nofile 1048576
LIMITS
  fi
  ok "file descriptor limit raised"
}

# ─────────────────────────────────────────────────────────────── firewall ────
configure_firewall() {
  local ports="$1"
  title "Firewall"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q .; then
    for p in $ports; do ufw allow "$p" >/dev/null 2>&1 || true; done
    ok "ufw: allowed $ports"
  elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
    for p in $ports; do firewall-cmd --permanent --add-port="$p" >/dev/null 2>&1 || true; done
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld: allowed $ports"
  else
    info "no managed firewall detected; make sure $ports are reachable"
  fi
  warn "keep the relay's exposed surface at 80 and 443 only — a host with a"
  warn "cluster of unusual open ports is found by scanning long before any"
  warn "single connection is analysed"
}

# ───────────────────────────────────────────────────────────── certificate ────
obtain_cert() {
  local domain="$1"
  CERT_FILE="/etc/letsencrypt/live/$domain/fullchain.pem"
  KEY_FILE="/etc/letsencrypt/live/$domain/privkey.pem"

  if [[ -f "$CERT_FILE" ]]; then
    ok "existing certificate for $domain"
    return
  fi

  title "Certificate for $domain"
  info "a real certificate for a real domain is not optional camouflage:"
  info "a self-signed cert on 443 is a signal on its own, whatever else"
  info "the connection looks like"

  command -v certbot >/dev/null || spin "installing certbot" pkg_install certbot

  if ! ss -ltn 2>/dev/null | grep -q ':80 '; then
    spin "requesting certificate (standalone, port 80)" \
      certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$domain"
  else
    warn "port 80 is in use; using webroot mode"
    ask WEBROOT "webroot path" "/var/www/html"
    spin "requesting certificate (webroot)" \
      certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$domain"
  fi

  [[ -f "$CERT_FILE" ]] || die "certbot did not produce $CERT_FILE"
  ok "certificate installed"

  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/serai.sh <<'HOOK'
#!/bin/sh
systemctl is-active --quiet serai-edge && systemctl restart serai-edge
exit 0
HOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/serai.sh
  ok "renewal hook installed"
}

# ─────────────────────────────────────────────────────────────── systemd ────
write_unit() {
  local role="$1" conf="$2" mem="$3"
  cat >"/etc/systemd/system/serai-$role.service" <<UNIT
[Unit]
Description=Serai $role (reverse tunnel)
Documentation=$REPO_URL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN $role -c $conf
Restart=always
RestartSec=2s
# Do not let a crash loop hammer the relay: a tight reconnect loop is both a
# load problem and a detectable pattern.
StartLimitBurst=20
StartLimitIntervalSec=300

# Go's garbage collector cannot see the cgroup limit on its own; without this
# a memory spike is an OOM kill instead of a collection.
Environment=GOMEMLIMIT=${mem}MiB
Environment=GOMAXPROCS=0

LimitNOFILE=1048576
# Binding 443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=$STATE_DIR
ReadOnlyPaths=$CONF_DIR

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

mem_budget() {
  local total
  total="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
  echo $((total * 70 / 100))
}

# ──────────────────────────────────────────────────────────── install edge ────
install_edge() {
  need_root; detect_os; ensure_deps

  title "Serai edge — the relay users connect to"
  kv "host" "$OS_NAME ($ARCH)"
  printf '\n'
  info "this host needs a real domain pointed at its IP, DNS-only."
  info "with Cloudflare or ArvanCloud, keep the record grey/unproxied:"
  info "you get the domain and the certificate, and pay nothing for CDN"
  info "bandwidth, because traffic goes straight here."
  printf '\n'

  ask DOMAIN   "tunnel domain (points at this server)"
  [[ -n "$DOMAIN" ]] || die "a domain is required"
  ask DECOY    "decoy site to mirror for probers" "https://www.lipsum.com"
  ask WSPATH   "websocket path" "/$(head -c 8 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 8)"
  ask PROFILE  "profile (speed / balanced / stealth)" "balanced"
  ask ALLOW    "ports an origin may claim" "443,8000-9000,10000-20000"

  ensure_go; build_binary
  obtain_cert "$DOMAIN"

  local psk
  psk="$("$BIN" keygen)"
  mkdir -p "$CONF_DIR" "$STATE_DIR"
  chmod 0700 "$CONF_DIR"
  printf '%s\n' "$psk" >"$CONF_DIR/psk"
  chmod 0600 "$CONF_DIR/psk"

  cat >"$CONF_DIR/edge.json" <<CONF
{
  "role": "edge",
  "name": "$(hostname -s)-edge",
  "profile": "$PROFILE",
  "log_level": "info",
  "psk_file": "$CONF_DIR/psk",
  "admin_addr": "127.0.0.1:9900",

  "server": {
    "control_addr": ":443",
    "quic_addr": ":443",
    "tunnel_sni": "$DOMAIN",
    "ws_path": "$WSPATH",
    "cert_file": "$CERT_FILE",
    "key_file": "$KEY_FILE",
    "decoy_upstream": "$DECOY",
    "allow_ports": "$ALLOW",
    "max_sessions": 8
  }
}
CONF
  chmod 0600 "$CONF_DIR/edge.json"
  ok "wrote $CONF_DIR/edge.json"

  "$BIN" check -c "$CONF_DIR/edge.json" >/dev/null || die "generated config is invalid"

  tune_kernel
  configure_firewall "80/tcp 443/tcp 443/udp"

  write_unit edge "$CONF_DIR/edge.json" "$(mem_budget)"
  spin "starting serai-edge" bash -c "systemctl enable --now serai-edge"
  sleep 1
  systemctl is-active --quiet serai-edge || { journalctl -u serai-edge -n 30 --no-pager; die "serai-edge failed to start"; }

  local pin
  pin="$("$BIN" pin -cert "$CERT_FILE")"

  printf '\n'; rule
  printf '%s  Edge is live. Paste this into the origin installer.%s\n' "$C_BOLD$C_MINT" "$C_RESET"
  rule
  kv "domain"        "$DOMAIN"
  kv "websocket path" "$WSPATH"
  kv "pre-shared key" "$psk"
  kv "certificate pin" "$pin"
  rule
  printf '  %sThe key is the only secret. Move it over an existing secure%s\n' "$C_DIM" "$C_RESET"
  printf '  %schannel, not over the link you are about to build.%s\n\n' "$C_DIM" "$C_RESET"
}

# ────────────────────────────────────────────────────────── install origin ────
install_origin() {
  need_root; detect_os; ensure_deps

  title "Serai origin — the host that runs 3x-ui / Xray"
  kv "host" "$OS_NAME ($ARCH)"
  printf '\n'
  info "nothing here needs an open port: this host dials the relay."
  printf '\n'

  ask DOMAIN  "the edge's domain"
  [[ -n "$DOMAIN" ]] || die "the edge domain is required"
  ask PSK     "pre-shared key from the edge installer"
  [[ -n "$PSK" ]] || die "the pre-shared key is required"
  ask WSPATH  "websocket path from the edge installer" "/ws"
  ask PROFILE "profile (speed / balanced / stealth)" "balanced"
  printf '\n'
  info "now the forwarding rules. The relay opens these ports; a user who"
  info "connects to them reaches the matching local port on this host."
  printf '\n'
  ask MAINPORT "main inbound port (same on both sides)" "443"
  ask SNILIST  "SNI that routes to it on the relay's 443" "vpn.$DOMAIN"
  ask EXTRA    "extra ports to forward (ranges allowed, blank for none)" "8000-9000"
  ask PANEL    "forward the panel's web port too? (port, or blank)" ""
  ask CARRIERS "parallel carriers" "3"

  ensure_go; build_binary

  mkdir -p "$CONF_DIR" "$STATE_DIR"
  chmod 0700 "$CONF_DIR"
  printf '%s\n' "$PSK" >"$CONF_DIR/psk"
  chmod 0600 "$CONF_DIR/psk"

  local forwards
  forwards=$(cat <<FWD
    {
      "name": "main",
      "proto": "tcp",
      "edge_ports": "$MAINPORT",
      "sni": ["$SNILIST"],
      "target": "127.0.0.1:$MAINPORT",
      "proxy_protocol": 2
    }
FWD
)
  if [[ -n "$EXTRA" ]]; then
    forwards+=$(cat <<FWD
,
    {
      "name": "inbounds",
      "proto": "tcp+udp",
      "edge_ports": "$EXTRA",
      "target_host": "127.0.0.1",
      "proxy_protocol": 2
    }
FWD
)
  fi
  if [[ -n "$PANEL" ]]; then
    forwards+=$(cat <<FWD
,
    {
      "name": "panel",
      "proto": "tcp",
      "edge_ports": "$PANEL",
      "target": "127.0.0.1:$PANEL"
    }
FWD
)
  fi

  cat >"$CONF_DIR/origin.json" <<CONF
{
  "role": "origin",
  "name": "$(hostname -s)-origin",
  "profile": "$PROFILE",
  "log_level": "info",
  "psk_file": "$CONF_DIR/psk",
  "admin_addr": "127.0.0.1:9900",

  "edge": {
    "paths": [
      {
        "transport": "quic",
        "addr": "$DOMAIN:443",
        "role": "data",
        "weight": 3
      },
      {
        "transport": "websocket",
        "url": "wss://$DOMAIN$WSPATH",
        "fingerprint": "chrome",
        "role": "both",
        "weight": 2,
        "headers": {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
          "Accept-Language": "en-US,en;q=0.9"
        }
      }
    ],
    "reconnect": { "min": "1s", "max": "120s", "factor": 1.8, "jitter": 0.3 }
  },

  "tuning": {
    "carriers": $CARRIERS
  },

  "forwards": [
$forwards
  ]
}
CONF
  chmod 0600 "$CONF_DIR/origin.json"
  ok "wrote $CONF_DIR/origin.json"

  "$BIN" check -c "$CONF_DIR/origin.json" || die "generated config is invalid"

  tune_kernel

  write_unit origin "$CONF_DIR/origin.json" "$(mem_budget)"
  spin "starting serai-origin" bash -c "systemctl enable --now serai-origin"
  sleep 2
  systemctl is-active --quiet serai-origin || { journalctl -u serai-origin -n 30 --no-pager; die "serai-origin failed to start"; }

  printf '\n'; rule
  printf '%s  Origin is live.%s\n' "$C_BOLD$C_MINT" "$C_RESET"
  rule
  printf '  %sNext, in 3x-ui:%s\n' "$C_BOLD" "$C_RESET"
  printf '    1. point each inbound at 127.0.0.1 on the port you forwarded\n'
  printf '    2. enable %sacceptProxyProtocol%s on those inbounds so the panel\n' "$C_TEAL" "$C_RESET"
  printf '       shows each user%ss real IP instead of 127.0.0.1\n' "'"
  printf '    3. hand users the relay address: %s%s:%s%s\n' "$C_AMBER" "$SNILIST" "$MAINPORT" "$C_RESET"
  rule
  printf '  %sWatch it:%s journalctl -u serai-origin -f\n' "$C_DIM" "$C_RESET"
  printf '  %sStatus:%s   curl -s localhost:9900/status\n\n' "$C_DIM" "$C_RESET"
}

# ──────────────────────────────────────────────────────────────── status ────
show_status() {
  banner
  for role in edge origin; do
    local unit="serai-$role"
    systemctl list-unit-files "$unit.service" >/dev/null 2>&1 || continue
    [[ -f "/etc/systemd/system/$unit.service" ]] || continue

    title "$unit"
    if systemctl is-active --quiet "$unit"; then
      kv "state" "${C_MINT}active${C_RESET}"
    else
      kv "state" "${C_ROSE}inactive${C_RESET}"
    fi
    kv "since"  "$(systemctl show -p ActiveEnterTimestamp --value "$unit")"
    kv "memory" "$(systemctl show -p MemoryCurrent --value "$unit" | awk '{ if ($1+0>0) printf "%.1f MiB", $1/1048576; else print "n/a" }')"

    if command -v curl >/dev/null; then
      local body
      body="$(curl -fsS --max-time 2 localhost:9900/status 2>/dev/null || true)"
      if [[ -n "$body" ]]; then
        printf '\n%s%s%s\n' "$C_DIM" "$body" "$C_RESET"
      fi
    fi
    printf '\n'
    journalctl -u "$unit" -n 8 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
  done
  printf '\n'
}

do_uninstall() {
  need_root
  confirm "remove serai, its units and its config?" || { info "cancelled"; return; }
  for role in edge origin; do
    systemctl disable --now "serai-$role" 2>/dev/null || true
    rm -f "/etc/systemd/system/serai-$role.service"
  done
  systemctl daemon-reload
  rm -f "$BIN" /etc/sysctl.d/99-serai.conf /etc/letsencrypt/renewal-hooks/deploy/serai.sh
  sysctl --system >/dev/null 2>&1 || true
  if confirm "also delete $CONF_DIR (contains the pre-shared key)?"; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    ok "config removed"
  else
    info "kept $CONF_DIR"
  fi
  ok "serai removed"
}

menu() {
  banner
  rule
  printf '    %s1%s  Install edge      %s— the relay, in-country, users dial it%s\n' "$C_BOLD$C_TEAL" "$C_RESET" "$C_DIM" "$C_RESET"
  printf '    %s2%s  Install origin    %s— the host with 3x-ui, dials out%s\n'       "$C_BOLD$C_TEAL" "$C_RESET" "$C_DIM" "$C_RESET"
  printf '    %s3%s  Status\n'                                                       "$C_BOLD$C_TEAL" "$C_RESET"
  printf '    %s4%s  Follow logs\n'                                                  "$C_BOLD$C_TEAL" "$C_RESET"
  printf '    %s5%s  Restart\n'                                                      "$C_BOLD$C_TEAL" "$C_RESET"
  printf '    %s6%s  Re-apply kernel tuning\n'                                       "$C_BOLD$C_TEAL" "$C_RESET"
  printf '    %s7%s  Uninstall\n'                                                    "$C_BOLD$C_ROSE" "$C_RESET"
  printf '    %s0%s  Quit\n'                                                         "$C_BOLD$C_SLATE" "$C_RESET"
  rule
  ask CHOICE "choose" "3"
  case "$CHOICE" in
    1) install_edge ;;
    2) install_origin ;;
    3) show_status ;;
    4) local u; u=$(installed_unit); journalctl -u "$u" -f ;;
    5) local u; u=$(installed_unit); systemctl restart "$u" && ok "restarted $u" ;;
    6) need_root; tune_kernel ;;
    7) do_uninstall ;;
    0) exit 0 ;;
    *) err "unknown choice"; exit 2 ;;
  esac
}

installed_unit() {
  if [[ -f /etc/systemd/system/serai-edge.service ]]; then echo serai-edge
  elif [[ -f /etc/systemd/system/serai-origin.service ]]; then echo serai-origin
  else die "serai is not installed here"; fi
}

case "${1:-menu}" in
  edge)      install_edge ;;
  origin)    install_origin ;;
  status)    show_status ;;
  tune)      need_root; tune_kernel ;;
  uninstall) do_uninstall ;;
  menu|"")   menu ;;
  *)         die "unknown command '$1' (edge|origin|status|tune|uninstall)" ;;
esac
