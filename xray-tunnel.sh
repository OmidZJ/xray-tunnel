#!/usr/bin/env bash
set -euo pipefail

TEMPLATE="/usr/local/etc/xray/config-template.json"
TARGET="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

usage() {
  cat <<'EOF'
Usage (non-interactive):
  xray-tunnel.sh setup /path/to/outbound.json [--only-ports "80,443,8080,10000-10100"]
  xray-tunnel.sh rollback

Interactive mode:
  Just run: xray-tunnel.sh
  - Choose: Setup Xray or Rollback
  - Enter ports to tunnel (blank = ALL TCP)
  - Paste your outbound JSON (press Ctrl+D when done)

Notes:
  --only-ports : Comma separated, supports ranges like 10000-10100.
EOF
}

# ---------- Helpers ----------
apply_redirect_rule() {
  local d="$1"
  if [[ "$d" == *"-"* ]]; then d="${d/-/:}"; fi
  iptables -t nat -A OUTPUT -p tcp --dport "$d" -j REDIRECT --to-ports 12346
}

ensure_jq() {
  command -v jq >/dev/null 2>&1 || {
    echo "[+] Installing jq ..."
    apt-get update -y && apt-get install -y jq
  }
}

install_or_update_xray() {
  echo "[+] Installing/Updating Xray ..."
  bash <(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install
}

ensure_template() {
  if [[ ! -f "$TEMPLATE" ]]; then
    echo "[+] Creating config-template.json ..."
    mkdir -p /usr/local/etc/xray
    cat > "$TEMPLATE" <<'JSON'
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "tag": "socks-in", "listen": "127.0.0.1", "port": 1081, "protocol": "socks", "settings": { "udp": true } },
    { "tag": "tproxy-in", "port": 12345, "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } } },
    { "tag": "redir-in", "port": 12346, "protocol": "dokodemo-door",
      "settings": { "network": "tcp", "followRedirect": true },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] } }
  ],
  "outbounds": [
    { "tag": "proxy", "protocol": "vless", "settings": { "vnext": [] }, "streamSettings": {} },
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": { "domainStrategy": "AsIs", "rules": [ { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" } ] }
}
JSON
  fi
}

build_config() {
  local OUTBOUND_FILE="$1"
  echo "[+] Building final config.json ..."
  jq --slurpfile ob "$OUTBOUND_FILE" '.outbounds[0] = $ob[0]' "$TEMPLATE" > "$TARGET"
}

restart_xray() {
  echo "[+] Testing and restarting Xray ..."
  "$XRAY_BIN" run -test -config "$TARGET"
  systemctl restart xray
  systemctl enable xray
}

flush_nat_output() {
  echo "[+] Flushing old iptables rules (nat/OUTPUT) ..."
  iptables -t nat -F OUTPUT || true
}

apply_iptables_rules() {
  local OUTBOUND_FILE="$1"
  local ONLY_PORTS="${2:-}"

  echo "[+] Applying iptables rules ..."
  XRAY_UID=$(id -u nobody 2>/dev/null || echo 65534)

  # Exceptions
  iptables -t nat -A OUTPUT -m owner --uid-owner ${XRAY_UID} -j RETURN
  iptables -t nat -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -t nat -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.1/32 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.53/32 -j RETURN

  # Exclude upstream server if literal IPv4
  SERVER_IP=$(jq -r '.settings.vnext[0].address // empty' "$OUTBOUND_FILE")
  if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    iptables -t nat -A OUTPUT -d "$SERVER_IP"/32 -j RETURN
  fi

  if [[ -n "$ONLY_PORTS" ]]; then
    echo "[+] Redirecting ONLY destination TCP ports: $ONLY_PORTS"
    IFS=',' read -r -a PORT_ARR <<< "$ONLY_PORTS"
    for p in "${PORT_ARR[@]}"; do
      p="$(echo "$p" | xargs)"
      [[ -z "$p" ]] && continue
      apply_redirect_rule "$p"
    done
  else
    echo "[+] Redirecting ALL destination TCP ports to redir-in"
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12346
  fi

  echo "[+] Installing iptables-persistent to save rules ..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
  netfilter-persistent save
}

do_rollback() {
  echo "[+] Flushing iptables rules..."
  iptables -t nat -F OUTPUT || true
  iptables -F || true
  iptables -t nat -F || true
  iptables -t mangle -F || true

  echo "[+] Stopping Xray..."
  systemctl stop xray || true
  systemctl disable xray || true

  echo "[+] Saving clean rules..."
  netfilter-persistent save || true

  echo "[+] Rollback complete. Networking restored to default."
}

interactive_setup() {
  echo "== Xray Tunnel • Interactive Setup =="
  echo
  # Ask ports
  read -r -p "Enter destination TCP ports to tunnel (comma/ranges), or leave blank for ALL: " ONLY_PORTS

  # Capture outbound JSON
  echo
  echo "Paste your outbound JSON below, then press Ctrl+D when finished:"
  OUTBOUND_FILE="$(mktemp)"
  cat > "$OUTBOUND_FILE"
  echo
  echo "[i] Validating outbound JSON..."
  ensure_jq
  jq empty "$OUTBOUND_FILE" || { echo "Invalid JSON"; rm -f "$OUTBOUND_FILE"; exit 1; }

  # Proceed
  ensure_jq
  install_or_update_xray
  ensure_template
  build_config "$OUTBOUND_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"

  rm -f "$OUTBOUND_FILE"
  echo
  echo "[✓] Setup complete!"
  echo "Test:"
  echo "  curl -4 -x socks5h://127.0.0.1:1081 https://ifconfig.me"
  echo "  curl -4 https://ifconfig.me"
}

interactive_menu() {
  echo "== Xray Tunnel Menu =="
  echo "1) Setup Xray tunnel"
  echo "2) Rollback (disable tunnel)"
  echo "q) Quit"
  echo
  read -r -p "Choose an option: " CH
  case "$CH" in
    1) interactive_setup ;;
    2) do_rollback ;;
    q|Q) exit 0 ;;
    *) echo "Invalid option"; exit 1 ;;
  esac
}

# ---------- Entry ----------
MODE="${1:-}"

# Interactive mode if no args
if [[ -z "${MODE}" ]]; then
  interactive_menu
  exit 0
fi

# Non-interactive (backward compatible)
if [[ "$MODE" == "rollback" ]]; then
  do_rollback
  exit 0
fi

if [[ "$MODE" == "setup" ]]; then
  OUTBOUND_FILE="${2:-}"
  ONLY_PORTS=""
  if [[ $# -ge 3 && "${3:-}" == "--only-ports" ]]; then
    ONLY_PORTS="${4:-}"
  fi

  if [[ -z "$OUTBOUND_FILE" || ! -f "$OUTBOUND_FILE" ]]; then
    usage; echo; echo "Error: missing or invalid outbound.json"; exit 1
  fi

  ensure_jq
  install_or_update_xray
  ensure_template
  build_config "$OUTBOUND_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"

  echo
  echo "[✓] Setup complete!"
  echo "Test:"
  echo "  curl -4 -x socks5h://127.0.0.1:1081 https://ifconfig.me"
  echo "  curl -4 https://ifconfig.me"
  exit 0
fi

usage; exit 1
