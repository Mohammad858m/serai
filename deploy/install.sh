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

# Six rows of the logo, each printed in its own shade so the wordmark reads as
# a gradient rather than a flat block.
banner() {
  local g=(
    $'\e[38;5;80m' $'\e[38;5;79m' $'\e[38;5;78m'
    $'\e[38;5;114m' $'\e[38;5;146m' $'\e[38;5;183m'
  )
  [[ -z "$C_TEAL" ]] && g=("" "" "" "" "" "")

  local rows=(
'  ███████╗ ███████╗ ██████╗   █████╗  ██╗'
'  ██╔════╝ ██╔════╝ ██╔══██╗ ██╔══██╗ ██║'
'  ███████╗ █████╗   ██████╔╝ ███████║ ██║'
'  ╚════██║ ██╔══╝   ██╔══██╗ ██╔══██║ ██║'
'  ███████║ ███████╗ ██║  ██║ ██║  ██║ ██║'
'  ╚══════╝ ╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝'
  )

  printf '\n'
  local i
  for i in "${!rows[@]}"; do
    printf '%s%s%s\n' "${g[i]}" "${rows[i]}" "$C_RESET"
  done
  printf '\n  %sa caravanserai for your traffic%s\n' "$C_DIM" "$C_RESET"
  printf '  %sreverse tunnel · multipath · browser-shaped TLS%s\n' "$C_SLATE" "$C_RESET"
  printf '\n'
  status_strip
}

# status_strip summarises what is installed and running, so the menu does not
# have to be read blind.
status_strip() {
  local hostline="unknown" ver="not installed"
  if [[ -r /etc/os-release ]]; then
    hostline="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-$ID}") · $(uname -m)"
  fi
  [[ -x "$BIN" ]] && ver="$("$BIN" version 2>/dev/null | awk '{print $2}')"

  rule
  printf '  %s%-8s%s ' "$C_SLATE" "host" "$C_RESET"
  pad_visible "$hostline" 38
  printf '%s%-8s%s %s\n' "$C_SLATE" "serai" "$C_RESET" "$ver"

  printf '  %s%-8s%s ' "$C_SLATE" "edge" "$C_RESET"
  pad_visible "$(role_state edge)" 38
  printf '%s%-8s%s %s\n' "$C_SLATE" "origin" "$C_RESET" "$(role_state origin)"
  rule
}

# pad_visible writes a string padded to a column width, ignoring ANSI escapes
# when measuring. printf's own %-Ns counts the escape bytes, which pushes every
# coloured cell out of alignment.
pad_visible() {
  local s="$1" want="$2" plain pad
  plain="$(printf '%s' "$s" | sed 's/\x1b\[[0-9;]*m//g')"
  printf '%s' "$s"
  pad=$(( want - ${#plain} ))
  (( pad > 0 )) && printf '%*s' "$pad" ''
}

# role_state renders one role's unit state plus a live carrier count.
role_state() {
  local role="$1" unit="serai-$1"
  [[ -f "/etc/systemd/system/$unit.service" ]] || { printf '%s—  not installed%s' "$C_DIM" "$C_RESET"; return; }

  if ! systemctl is-active --quiet "$unit"; then
    printf '%s● inactive%s' "$C_ROSE" "$C_RESET"
    return
  fi

  local n=""
  if command -v curl >/dev/null; then
    n="$(curl -fsS --max-time 2 localhost:9900/status 2>/dev/null \
         | grep -o '"transport"' | wc -l | tr -d ' ')"
  fi
  if [[ -n "$n" && "$n" != 0 ]]; then
    printf '%s● active%s · %s carrier(s)' "$C_MINT" "$C_RESET" "$n"
  else
    printf '%s● active%s' "$C_MINT" "$C_RESET"
  fi
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

# public_ip reports this host's reachable address.
#
# It reads the kernel's own source address for an off-network route first, which
# is correct on a VPS with a public address attached directly and needs no
# outbound request at all. That matters here: the relay often sits on a network
# where the usual echo services are unreachable, and falling straight to curl
# left the installer printing a placeholder where the operator needed a number
# to paste into the other half.
public_ip() {
  local ip svc
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p')"
  if [[ -n "$ip" ]] && ! is_private "$ip"; then
    printf '%s' "$ip"
    return
  fi

  # Behind NAT the local address says nothing, so ask -- several of them,
  # because any single service may be blocked from here.
  for svc in https://api.ipify.org https://ifconfig.me https://icanhazip.com https://ipinfo.io/ip; do
    ip="$(curl -fsS --max-time 4 "$svc" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s' "$ip"
      return
    fi
  done

  printf '%s' "${1:-<this host IP>}"
}

is_private() {
  case "$1" in
    10.*|127.*|169.254.*|192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    *) return 1 ;;
  esac
}

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

# go_tidy and go_build run as functions rather than nested "bash -c" strings.
# An earlier version built the -ldflags argument inside a quoted shell string;
# the command substitution for the version never ran and the whole thing was
# handed to the linker as flags, which answered with its usage text.
go_tidy() {
  cd "$1" || return 1
  GOFLAGS=-mod=mod go mod tidy
}

go_build() {
  local src="$1" ver="$2"
  cd "$src" || return 1
  CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$ver" \
    -o "$BIN" ./cmd/serai
}

build_binary() {
  local src ver
  if [[ -f "$(dirname "$0")/../go.mod" ]]; then
    src="$(cd "$(dirname "$0")/.." && pwd)"
    info "building from local checkout at $src"
  else
    src="$(mktemp -d)"
    spin "fetching source" git clone --depth 1 "$REPO_URL" "$src"
  fi
  # Resolve modules before building: "go build" will not write go.sum entries
  # on its own, and the repository ships without a go.sum.
  #
  # proxy.golang.org is served by Google and is not reachable from every
  # network — notably not from inside Iran, which is exactly where the relay
  # runs. The list falls through to mirrors and then to direct VCS fetches.
  export GOTOOLCHAIN=local
  export GOPROXY="${SERAI_GOPROXY:-https://proxy.golang.org,https://goproxy.io,https://goproxy.cn,direct}"

  if ! spin "resolving dependencies" go_tidy "$src"; then
    warn "could not fetch modules from any proxy"
    warn "if this network blocks them, either set a reachable mirror:"
    warn "    SERAI_GOPROXY=https://your-mirror,direct bash $0 edge"
    warn "or build on the other server and copy the binary to $BIN"
    return 1
  fi

  ver="$(git -C "$src" describe --tags --always 2>/dev/null || echo dev)"
  if ! spin "building serai (static, stripped)" go_build "$src" "$ver"; then
    return 1
  fi

  chmod 0755 "$BIN"
  ok "installed $("$BIN" version)"
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
# port80_process names whatever is listening on 80, for a useful message
# instead of "port 80 is in use".
port80_process() {
  ss -ltnp 2>/dev/null |
    awk '$4 ~ /:80$/ {print; exit}' |
    sed -n 's/.*(("\([^"]*\)".*/\1/p'
}

# port80_unit maps that listener back to its systemd unit via the cgroup, so
# the installer can offer to stop the right thing rather than guessing nginx.
port80_unit() {
  local pid
  pid="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:80$/ {print; exit}' |
         sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
  [[ -n "$pid" && -r "/proc/$pid/cgroup" ]] || return 0
  grep -o '[^/]*\.service' "/proc/$pid/cgroup" 2>/dev/null | head -1
}

# certbot_standalone issues the certificate on a free port 80, recording hooks
# so unattended renewal works the same way three months from now. Without the
# hooks, renewal silently fails on a host where something else owns port 80 --
# and the failure surfaces as an expired certificate, not as an error anyone
# was watching for.
certbot_standalone() {
  local domain="$1" unit="${2:-}"
  local -a hooks=()
  if [[ -n "$unit" ]]; then
    hooks=(--pre-hook "systemctl stop $unit" --post-hook "systemctl start $unit")
  fi
  spin "requesting certificate (standalone, port 80)" \
    certbot certonly --standalone --non-interactive --agree-tos \
      --register-unsafely-without-email "${hooks[@]}" -d "$domain"
}

# probe_webroot verifies that the challenge directory is actually served over
# HTTP before a certbot attempt is spent on it. Let's Encrypt rate-limits
# failures, and a wrong webroot is the most common way this step fails.
probe_webroot() {
  local domain="$1" root="$2"
  local dir="$root/.well-known/acme-challenge"
  local token body
  token="serai-probe-$$-$RANDOM"

  mkdir -p "$dir" 2>/dev/null || return 1
  printf '%s' "$token" >"$dir/$token" 2>/dev/null || return 1
  body="$(curl -fsS --max-time 10 "http://$domain/.well-known/acme-challenge/$token" 2>/dev/null || true)"
  rm -f "$dir/$token"

  [[ "$body" == "$token" ]]
}

# make_self_signed issues a long-lived self-signed certificate for a name that
# need not exist in DNS at all.
#
# This exists because a relay is often brought up before a domain is pointed at
# it, or on a network where inbound port 80 is intercepted and the ACME HTTP
# challenge can never succeed. The SNI is only a label the two halves agree on:
# the origin dials the relay by IP and claims this name, and pins the public
# key, so there is no certificate authority in the path and nothing to verify
# by DNS.
#
# It is strictly weaker camouflage. Scanning 443 for self-signed certificates
# is the cheapest way there is to find a relay, and a prober that finds one
# learns immediately that no real website lives here, which makes the decoy
# pointless. Use it to get a tunnel working, then move to a real certificate.
make_self_signed() {
  local name="$1"
  CERT_FILE="$CONF_DIR/self.crt"
  KEY_FILE="$CONF_DIR/self.key"

  mkdir -p "$CONF_DIR"
  chmod 0700 "$CONF_DIR"

  if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    ok "reusing the existing self-signed certificate"
    return
  fi

  title "Self-signed certificate for $name"
  command -v openssl >/dev/null || spin "installing openssl" pkg_install openssl

  # P-256 rather than RSA: smaller handshake, and ECDSA is what current
  # browsers negotiate, so the handshake looks less unusual.
  spin "generating key and certificate" \
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$KEY_FILE" -out "$CERT_FILE" -days 3650 \
      -subj "/CN=$name" -addext "subjectAltName=DNS:$name"

  chmod 0600 "$KEY_FILE"
  chmod 0644 "$CERT_FILE"
  ok "self-signed certificate written to $CERT_FILE"

  warn "the origin must pin this key, because there is no CA to verify it."
  warn "The pin is printed at the end of this run."
}

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

  # Let's Encrypt has to fetch a file over plain HTTP on port 80. Three ways to
  # arrange that, tried in order of reliability rather than convenience.
  if ! ss -ltn 2>/dev/null | grep -q ':80 '; then
    certbot_standalone "$domain"
  else
    local holder unit
    holder="$(port80_process)"
    unit="$(port80_unit)"
    warn "port 80 is held by ${holder:-an unknown process}${unit:+ ($unit)}"

    if [[ -n "$unit" ]] && confirm "stop $unit for a few seconds and use standalone mode?"; then
      # The stop and start are handed to certbot as hooks rather than done
      # here, so that unattended renewal repeats them. certbot runs the post
      # hook even when the attempt fails; the explicit start below covers the
      # case where certbot is killed outright, because leaving someone's web
      # server down is worse than not getting a certificate.
      certbot_standalone "$domain" "$unit" || true
      systemctl start "$unit" >/dev/null 2>&1 || true
    else
      info "webroot mode: certbot writes the challenge into a directory that"
      info "the server on port 80 must already serve"
      ask WEBROOT "webroot path" "/var/www/html"

      # Prove the path is actually reachable before spending a certbot attempt.
      # Let's Encrypt rate-limits failures, and a 404 from the wrong webroot is
      # the single most common way this step fails.
      if probe_webroot "$domain" "$WEBROOT"; then
        ok "challenge directory is reachable over http"
        spin "requesting certificate (webroot)" \
          certbot certonly --webroot -w "$WEBROOT" --non-interactive --agree-tos \
            --register-unsafely-without-email -d "$domain"
      else
        err "http://$domain/.well-known/acme-challenge/ does not serve files"
        err "from $WEBROOT — certbot would fail with a 404"
        warn "either point this at the document root of whatever holds port 80,"
        warn "or stop that service and re-run so standalone mode can be used"
        return 1
      fi
    fi
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

  # Check 443 before asking anything else. The relay routes by SNI on raw TCP,
  # so it cannot sit behind another web server on that port -- and finding that
  # out after building, certificating and configuring wastes the whole run.
  local p443 u443
  p443="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:443$/ {print; exit}' | sed -n 's/.*(("\([^"]*\)".*/\1/p')"
  if [[ -n "$p443" && "$p443" != serai ]]; then
    u443="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:443$/ {print; exit}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p')"
    [[ -n "$u443" && -r "/proc/$u443/cgroup" ]] &&
      u443="$(grep -o '[^/]*\.service' "/proc/$u443/cgroup" 2>/dev/null | head -1)" || u443=""
    err "tcp/443 is held by $p443${u443:+ ($u443)}"
    warn "the relay needs 443 to itself: it reads the SNI off raw TCP and"
    warn "forwards the bytes untouched, so it cannot run behind a web server."
    warn "Port 80 can stay where it is."
    if [[ -n "$u443" ]]; then
      confirm "stop and disable $u443 on 443?" || die "free tcp/443 and run this again"
      systemctl stop "$u443" && ok "stopped $u443"
      warn "$u443 is stopped but still enabled; it will fight for 443 on reboot"
      confirm "disable $u443 at boot too?" && systemctl disable "$u443" >/dev/null 2>&1 && ok "disabled $u443"
    else
      die "free tcp/443 and run this again"
    fi
  fi

  local SELF_SIGNED=""
  info "leave the next answer blank to self-sign for testing, with no domain"
  info "and no certificate authority."
  ask DOMAIN   "tunnel domain (points at this server)"
  if [[ -z "$DOMAIN" ]]; then
    SELF_SIGNED=1
    info "testing mode: the name below only has to match on both halves,"
    info "it is never looked up in DNS"
    ask DOMAIN "name for the self-signed certificate" "tun.internal"
  fi
  ask DECOY    "decoy site to mirror for probers" "https://www.lipsum.com"
  ask WSPATH   "websocket path" "/$(head -c 8 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 8)"
  ask PROFILE  "profile (speed / balanced / stealth)" "balanced"
  printf '\n'
  info "the next answer limits which ports an origin may make this relay"
  info "open. Every inbound port you forward has to fall inside it, so keep"
  info "it a range, not a single port. 443 is served by SNI and needs no"
  info "entry. You can widen it later in $CONF_DIR/edge.json."
  # Keep asking until the answer is a range or the operator insists. A single
  # port here silently refuses every forward the origin asks for, which is a
  # confusing failure to debug from the other end.
  while true; do
    ask ALLOW "port range an origin may open (ranges ok)" "8000-9000,10000-20000"
    [[ -n "$ALLOW" ]] || continue
    if [[ "$ALLOW" == *-* || "$ALLOW" == *,* ]]; then
      break
    fi
    warn "'$ALLOW' is a single port — the origin will only be able to forward"
    warn "that one port, and anything else it asks for will be refused"
    if confirm "keep '$ALLOW' anyway?"; then
      break
    fi
  done

  ensure_go; build_binary
  if [[ -n "$SELF_SIGNED" ]]; then
    make_self_signed "$DOMAIN"
  else
    obtain_cert "$DOMAIN"
  fi

  mkdir -p "$CONF_DIR" "$STATE_DIR"
  chmod 0700 "$CONF_DIR"

  # Keep an existing key across re-runs. Re-running the installer is the normal
  # way to recover from a failed certificate step, and silently minting a new
  # key there would break an origin that is already paired -- with no error on
  # this side to explain why.
  local psk
  if [[ -s "$CONF_DIR/psk" ]]; then
    psk="$(cat "$CONF_DIR/psk")"
    ok "reusing the existing pre-shared key"
  else
    psk="$("$BIN" keygen)"
    printf '%s\n' "$psk" >"$CONF_DIR/psk"
  fi
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
  kv "tunnel name"    "$DOMAIN"
  kv "relay address"  "$(public_ip):443"
  kv "websocket path" "$WSPATH"
  kv "allowed ports"  "$ALLOW  (plus 443 via SNI)"
  kv "pre-shared key" "$psk"
  kv "certificate pin" "$pin"
  rule
  printf '  %sThe key is the only secret. Move it over an existing secure%s\n' "$C_DIM" "$C_RESET"
  printf '  %schannel, not over the link you are about to build.%s\n' "$C_DIM" "$C_RESET"

  if [[ -n "$SELF_SIGNED" ]]; then
    printf '\n'
    warn "this relay is self-signed, so the origin needs the pin above and"
    warn "will connect by address rather than by name."
    warn "Anyone scanning 443 can tell there is no real site here. Move to a"
    warn "real certificate before this carries traffic you care about."
  fi
  printf '\n'
}

# ────────────────────────────────────────────────────────── install origin ────
install_origin() {
  need_root; detect_os; ensure_deps

  title "Serai origin — the host that runs 3x-ui / Xray"
  kv "host" "$OS_NAME ($ARCH)"
  printf '\n'
  info "nothing here needs an open port: this host dials the relay."
  printf '\n'

  ask DOMAIN  "the relay's tunnel name (as the edge installer printed it)"
  [[ -n "$DOMAIN" ]] || die "the relay's tunnel name is required"
  ask EDGEADDR "the relay's address, host:port (blank to resolve $DOMAIN)" ""
  ask PSK     "pre-shared key from the edge installer"
  [[ -n "$PSK" ]] || die "the pre-shared key is required"
  ask WSPATH  "websocket path from the edge installer" "/ws"
  printf '\n'
  info "if the relay uses a self-signed certificate, paste the pin the edge"
  info "installer printed. Leave blank when the relay has a real certificate."
  ask PIN     "certificate pin (sha256/...)" ""
  ask PROFILE "profile (speed / balanced / stealth)" "balanced"
  printf '\n'
  info "now the forwarding rules. The relay opens these ports; a user who"
  info "connects to them reaches the matching local port on this host."
  printf '\n'
  ask MAINPORT "main inbound port (same on both sides)" "443"
  if [[ -n "$PIN" ]]; then
    # With a self-signed relay there is normally no DNS for the tunnel name,
    # so routing user traffic by SNI would mean inventing a second name that
    # also resolves nowhere. A plain port is the honest default for a test.
    info "self-signed relay: forwarding by port rather than by SNI, since the"
    info "tunnel name does not resolve"
    SNILIST=""
  else
    ask SNILIST "SNI that routes to it on the relay's 443" "vpn.$DOMAIN"
  fi
  ask EXTRA    "extra ports to forward (ranges allowed, blank for none)" "8000-9000"
  ask PANEL    "forward the panel's web port too? (port, or blank)" ""
  ask CARRIERS "parallel carriers" "3"

  # A self-signed relay cannot be verified by a CA, so the pin is the only
  # thing standing between this tunnel and anyone who can answer on that
  # address. Refuse to disable verification without one.
  local VERIFY_BLOCK=""
  if [[ -n "$PIN" ]]; then
    VERIFY_BLOCK="
    \"pinned_spki\": [\"${PIN#sha256/}\"],
    \"insecure\": true,"
  fi

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
      "edge_ports": "$MAINPORT",${SNILIST:+
      \"sni\": [\"$SNILIST\"],}
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
        "addr": "${EDGEADDR:-$DOMAIN:443}",
        "host": "$DOMAIN",
        "role": "data",
        "weight": 3
      },
      {
        "transport": "websocket",
        "url": "wss://$DOMAIN$WSPATH",${EDGEADDR:+
        \"edge_addr\": \"$EDGEADDR\",}
        "host": "$DOMAIN",
        "fingerprint": "chrome",
        "role": "both",
        "weight": 2,
        "headers": {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
          "Accept-Language": "en-US,en;q=0.9"
        }
      }
    ],$VERIFY_BLOCK
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

# ─────────────────────────────────────────────────────── extra operations ────
installed_unit() {
  if [[ -f /etc/systemd/system/serai-edge.service ]]; then echo serai-edge
  elif [[ -f /etc/systemd/system/serai-origin.service ]]; then echo serai-origin
  else return 1; fi
}

installed_conf() {
  case "$(installed_unit 2>/dev/null)" in
    serai-edge)   echo "$CONF_DIR/edge.json" ;;
    serai-origin) echo "$CONF_DIR/origin.json" ;;
    *) return 1 ;;
  esac
}

require_install() {
  installed_unit >/dev/null 2>&1 || { err "serai is not installed on this host"; return 1; }
}

# json_field pulls one string value out of the config without needing jq,
# which is not installed on a fresh VPS.
json_field() {
  grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null |
    head -1 | sed 's/.*:[[:space:]]*"\(.*\)"/\1/'
}

show_pairing() {
  local conf; conf="$(installed_conf)" || { err "nothing installed here"; return 1; }
  title "Pairing details"

  if [[ -r "$CONF_DIR/psk" ]]; then
    kv "pre-shared key" "$(cat "$CONF_DIR/psk")"
  else
    warn "no key file at $CONF_DIR/psk"
  fi

  local sni ws cert
  sni="$(json_field "$conf" tunnel_sni)"
  ws="$(json_field "$conf" ws_path)"
  cert="$(json_field "$conf" cert_file)"
  [[ -n "$sni" ]] && kv "tunnel domain" "$sni"
  [[ -n "$ws" ]]  && kv "websocket path" "$ws"
  if [[ -n "$cert" && -r "$cert" && -x "$BIN" ]]; then
    kv "certificate pin" "$("$BIN" pin -cert "$cert" 2>/dev/null || echo '(unreadable)')"
  fi

  printf '\n  %sMove the key over a channel you already trust, never over the%s\n' "$C_DIM" "$C_RESET"
  printf '  %slink you are about to build with it.%s\n' "$C_DIM" "$C_RESET"
}

edit_config() {
  local conf unit
  conf="$(installed_conf)" || { err "nothing installed here"; return 1; }
  unit="$(installed_unit)"

  "${EDITOR:-nano}" "$conf"

  if [[ -x "$BIN" ]] && "$BIN" check -c "$conf" >/dev/null 2>&1; then
    ok "config is valid"
    confirm "restart $unit now?" && systemctl restart "$unit" && ok "restarted"
  else
    err "config is NOT valid - the service will refuse to start"
    [[ -x "$BIN" ]] && "$BIN" check -c "$conf" 2>&1 | sed 's/^/    /'
  fi
}

validate_config() {
  local conf; conf="$(installed_conf)" || { err "nothing installed here"; return 1; }
  [[ -x "$BIN" ]] || { err "$BIN is missing"; return 1; }
  title "serai check"
  "$BIN" check -c "$conf" 2>&1 | sed 's/^/  /'
}

# diagnose walks the things that actually break a deployment, in the order
# they break: name resolution, port availability, certificate validity, and
# finally whether the two halves found each other.
diagnose() {
  local conf; conf="$(installed_conf)" || { err "nothing installed here"; return 1; }
  local unit; unit="$(installed_unit)"

  title "Diagnostics"

  local myip; myip="$(public_ip '?')"
  kv "public ip" "$myip"

  local sni; sni="$(json_field "$conf" tunnel_sni)"
  if [[ -n "$sni" ]]; then
    local resolved
    resolved="$(getent ahostsv4 "$sni" 2>/dev/null | awk 'NR==1{print $1}')"
    [[ -z "$resolved" ]] && resolved="$(dig +short "$sni" 2>/dev/null | head -1)"
    if [[ -z "$resolved" ]]; then
      err "$sni does not resolve"
    elif [[ "$resolved" == "$myip" ]]; then
      ok "$sni resolves here ($resolved)"
    else
      err "$sni resolves to $resolved, not to this host ($myip)"
      warn "certbot cannot validate, and users will not reach this relay"
    fi
  fi

  printf '\n'
  local p who
  for p in 80 443; do
    who="$(ss -ltnp 2>/dev/null | awk -v P=":$p" '$4 ~ P"$" {print $NF; exit}')"
    if [[ -z "$who" ]]; then
      info "tcp/$p free"
    elif [[ "$who" == *serai* ]]; then
      ok "tcp/$p held by serai"
    else
      warn "tcp/$p held by $who"
    fi
  done
  if ss -lunp 2>/dev/null | grep -q ':443 '; then
    ok "udp/443 bound (quic)"
  else
    info "udp/443 not bound - quic disabled or unavailable"
  fi

  local cert; cert="$(json_field "$conf" cert_file)"
  if [[ -n "$cert" && -r "$cert" ]]; then
    printf '\n'
    local until days
    until="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)"
    days=$(( ( $(date -d "$until" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
    if (( days > 20 )); then
      ok "certificate valid for $days more days"
    elif (( days > 0 )); then
      warn "certificate expires in $days days"
    else
      err "certificate is expired or unreadable"
    fi
  fi

  printf '\n'
  local body n
  body="$(curl -fsS --max-time 3 localhost:9900/status 2>/dev/null)"
  if [[ -z "$body" ]]; then
    err "admin endpoint silent - is $unit running?"
    journalctl -u "$unit" -n 10 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
  else
    n="$(printf '%s' "$body" | grep -c '"transport"' || true)"
    if [[ "$n" == 0 ]]; then
      err "no carriers: this half is up but the two have not paired"
      warn "check that both sides hold the same key, and that the origin can"
      warn "reach this host on 443"
    else
      ok "$n carrier(s) established"
    fi
  fi
  printf '\n'
}

do_update() {
  need_root; require_install || return 1
  detect_os; ensure_deps; ensure_go

  local unit conf
  unit="$(installed_unit)"
  conf="$(installed_conf)"

  build_binary || return 1

  if "$BIN" check -c "$conf" >/dev/null 2>&1; then
    systemctl restart "$unit" && ok "updated and restarted $unit"
  else
    err "the new binary rejects the existing config; not restarting"
    "$BIN" check -c "$conf" 2>&1 | sed 's/^/    /'
  fi
}

rotate_key() {
  need_root; require_install || return 1
  [[ -x "$BIN" ]] || { err "$BIN is missing"; return 1; }

  warn "a new key breaks the tunnel until the OTHER server holds the same key."
  warn "Rotate here first, then paste the new key on the other side."
  confirm "generate a new pre-shared key?" || { info "cancelled"; return; }

  local new; new="$("$BIN" keygen)"
  cp -a "$CONF_DIR/psk" "$CONF_DIR/psk.previous" 2>/dev/null || true
  printf '%s\n' "$new" >"$CONF_DIR/psk"
  chmod 0600 "$CONF_DIR/psk"
  systemctl restart "$(installed_unit)"

  rule
  kv "new key" "$new"
  kv "previous key kept at" "$CONF_DIR/psk.previous"
  rule
  warn "the tunnel stays down until the other server has this key"
}

service_control() {
  require_install || return 1
  local unit; unit="$(installed_unit)"
  printf '   %s1%s start    %s2%s stop    %s3%s restart\n' \
    "$C_BOLD$C_TEAL" "$C_RESET" "$C_BOLD$C_TEAL" "$C_RESET" "$C_BOLD$C_TEAL" "$C_RESET"
  ask SVC "action" "3"
  case "$SVC" in
    1) systemctl start "$unit"   && ok "started $unit" ;;
    2) systemctl stop "$unit"    && ok "stopped $unit" ;;
    3) systemctl restart "$unit" && ok "restarted $unit" ;;
    *) err "unknown action" ;;
  esac
}

# ───────────────────────────────────────────────────────────────── menu ────
group() {
  local dashes=$((W - ${#1} - 3))
  (( dashes < 0 )) && dashes=0
  printf '\n  %s%s%s %s%s%s\n' \
    "$C_BOLD$C_PLUM" "$1" "$C_RESET" \
    "$C_SLATE" "$(printf '─%.0s' $(seq 1 $dashes))" "$C_RESET"
}

item() {
  printf '   %s%2s%s  %-13s %s%s%s\n' \
    "$C_BOLD$C_TEAL" "$1" "$C_RESET" "$2" "$C_DIM" "$3" "$C_RESET"
}

danger() {
  printf '   %s%2s%s  %-13s %s%s%s\n' \
    "$C_BOLD$C_ROSE" "$1" "$C_RESET" "$2" "$C_DIM" "$3" "$C_RESET"
}

menu() {
  local u
  while true; do
    banner

    group "install"
    item 1 "edge"      "relay, in-country - users dial this host"
    item 2 "origin"    "the host with 3x-ui - dials out, no open port"

    group "operate"
    item 3 "status"    "carriers, traffic, sessions"
    item 4 "logs"      "follow the journal"
    item 5 "service"   "start / stop / restart"

    group "pair and configure"
    item 6 "pairing"   "key, domain and pin for the other server"
    item 7 "edit"      "open the config, validated on save"
    item 8 "validate"  "serai check"

    group "maintain"
    item   9 "diagnose"   "dns, ports, certificate, carriers"
    item  10 "tune"       "re-apply kernel tuning"
    item  11 "update"     "rebuild from source and restart"
    danger 12 "rotate key" "new pre-shared key - breaks the other side"
    danger 13 "uninstall"  "remove binary, units and tuning"

    printf '\n'
    item 0 "quit" ""
    rule
    ask CHOICE "choose" ""

    case "$CHOICE" in
      1)  install_edge ;;
      2)  install_origin ;;
      3)  show_status ;;
      4)  if u="$(installed_unit)"; then journalctl -u "$u" -f; else err "serai is not installed here"; fi ;;
      5)  service_control ;;
      6)  show_pairing ;;
      7)  edit_config ;;
      8)  validate_config ;;
      9)  diagnose ;;
      10) need_root; tune_kernel ;;
      11) do_update ;;
      12) rotate_key ;;
      13) do_uninstall ;;
      0|q|quit) exit 0 ;;
      "") continue ;;
      *)  err "unknown choice '$CHOICE'" ;;
    esac

    printf '\n  %spress enter to return to the menu%s ' "$C_DIM" "$C_RESET"
    read -r _ </dev/tty || true
  done
}

case "${1:-menu}" in
  edge)      install_edge ;;
  origin)    install_origin ;;
  status)    show_status ;;
  diagnose)  diagnose ;;
  pairing)   show_pairing ;;
  update)    do_update ;;
  tune)      need_root; tune_kernel ;;
  uninstall) do_uninstall ;;
  menu|"")   menu ;;
  *)         die "unknown command '$1' (edge|origin|status|diagnose|pairing|update|tune|uninstall)" ;;
esac
