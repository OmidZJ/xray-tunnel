#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
OUTBOUND_FILE="${2:-}"
TEMPLATE="/usr/local/etc/xray/config-template.json"
TARGET="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

if [[ "$MODE" != "setup" && "$MODE" != "rollback" ]]; then
  echo "Usage:"
  echo "  $0 setup /path/to/outbound.json   # install & configure Xray"
  echo "  $0 rollback                       # remove iptables rules & stop Xray"
  exit 1
fi

if [[ "$MODE" == "setup" ]]; then
  if [[ -z "$OUTBOUND_FILE" ]]; then
    echo "Error: missing outbound.json file"
    exit 1
  fi
  if [[ ! -f "$OUTBOUND_FILE" ]]; then
    echo "File not found: $OUTBOUND_FILE"
    exit 1
  fi

  command -v jq >/dev/null 2>&1 || {
    echo "[+] Installing jq ..."
    apt-get update -y && apt-get install -y jq
  }

  echo "[+] Installing/Updating Xray ..."
  bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install

  # Create template if not exists
  if [[ ! -f "$TEMPLATE" ]]; then
    echo "[+] Creating config-template.json ..."
    mkdir -p /usr/local/etc/xray
    cat > "$TEMPLATE" <<'JSON'
{
  "log": { "loglevel": "warning" },

  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 1081,
      "protocol": "socks",
      "settings": { "udp": true }
    },
    {
      "tag": "tproxy-in",
      "port": 12345,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp,udp", "followRedirect": true },
      "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
    },
    {
      "tag": "redir-in",
      "port": 12346,
      "protocol": "dokodemo-door",
      "settings": { "network": "tcp", "followRedirect": true },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],

  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": { "vnext": [] },
      "streamSettings": {}
    },
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block", "protocol": "blackhole" }
  ],

  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }
    ]
  }
}
JSON
  fi

  echo "[+] Building final config.json ..."
  jq --slurpfile ob "$OUTBOUND_FILE" '.outbounds[0] = $ob[0]' "$TEMPLATE" > "$TARGET"

  echo "[+] Testing and restarting Xray ..."
  $XRAY_BIN run -test -config "$TARGET"
  systemctl restart xray
  systemctl enable xray

  echo "[+] Flushing old iptables rules ..."
  iptables -t nat -F OUTPUT || true

  echo "[+] Applying iptables rules ..."
  XRAY_UID=$(id -u nobody 2>/dev/null || echo 65534)

  iptables -t nat -A OUTPUT -m owner --uid-owner ${XRAY_UID} -j RETURN
  iptables -t nat -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -t nat -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.1/32 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.53/32 -j RETURN

  SERVER_IP=$(jq -r '.settings.vnext[0].address' "$OUTBOUND_FILE")
  if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    iptables -t nat -A OUTPUT -d "$SERVER_IP"/32 -j RETURN
  fi

  iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12346

  echo "[+] Installing iptables-persistent to save rules ..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
  netfilter-persistent save

  echo "[+] Setup complete!"
  echo "  Test with:"
  echo "    curl -4 -x socks5h://127.0.0.1:1081 https://ifconfig.me"
  echo "    curl -4 https://ifconfig.me"
fi

if [[ "$MODE" == "rollback" ]]; then
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
fi
