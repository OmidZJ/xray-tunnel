#!/usr/bin/env bash
set -euo pipefail

TEMPLATE="/usr/local/etc/xray/config-template.json"
TARGET="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

usage() {
  cat <<'EOF'
Usage (non-interactive):
  xray-tunnel.sh setup /path/to/config_input [--only-ports "80,443,8080,10000-10100"]
    - config_input can be:
        * a v2ray link: vmess://..., vless://..., trojan://...
        * a JSON file: full Xray client config (will extract first outbound)
        * a JSON file: a single outbound object

  xray-tunnel.sh rollback

Interactive mode:
  Just run: xray-tunnel.sh
  - Choose: Setup Xray or Rollback
  - Enter ports to tunnel (blank = ALL TCP)
  - Paste your v2ray config/link (Ctrl+D to finish)

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

ensure_tools() {
  command -v jq >/dev/null 2>&1 || {
    echo "[+] Installing jq ..."
    apt-get update -y && apt-get install -y jq
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "[+] Installing python3 ..."
    apt-get update -y && apt-get install -y python3
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

# Convert arbitrary user input (link or JSON) to a single outbound JSON
to_outbound_json() {
  # $1: path to input file OR a direct link string
  local INPUT="$1"
  local TMP_OUT
  TMP_OUT="$(mktemp)"

  # If it's a file, read contents; else treat as literal string (link)
  local CONTENT
  if [[ -f "$INPUT" ]]; then
    CONTENT="$(cat "$INPUT")"
  else
    CONTENT="$INPUT"
  fi

  # Pass CONTENT via env to Python (avoid mixing heredoc with here-string/pipe)
  XRAY_INPUT="$CONTENT" python3 - "$TMP_OUT" <<'PY'
import sys, json, base64, urllib.parse, os

out_path = sys.argv[1]
raw = os.environ.get("XRAY_INPUT","").strip()

def b64fix(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = (4 - len(s) % 4) % 4
    return s + ('=' * pad)

def outbound_from_vmess(link):
    b64 = link.split('://',1)[1]
    data = json.loads(base64.b64decode(b64fix(b64)).decode('utf-8','ignore'))
    add = data.get('add'); port = int(data.get('port', 0) or 0)
    uid = data.get('id'); aid = int(data.get('aid', 0) or 0)
    net = data.get('net') or 'tcp'
    host = data.get('host') or ''
    path = data.get('path') or ''
    tls = data.get('tls') or ''
    sni = data.get('sni') or data.get('host') or ''
    scy = data.get('scy') or 'auto'
    stream = {"network": net}
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        if host: ws["headers"]["Host"] = host
        stream["wsSettings"] = ws
    elif net in ('grpc','gun'):
        svc = path.lstrip("/") if path else ""
        stream["grpcSettings"] = {"serviceName": svc}
    if tls in ('tls','reality'):
        stream["security"] = 'tls' if tls=='tls' else 'reality'
        if sni:
            key = "tlsSettings" if tls=='tls' else "realitySettings"
            stream[key] = {"serverName": sni}
    return {
        "tag":"proxy","protocol":"vmess",
        "settings":{"vnext":[{"address":add,"port":port,"users":[{"id":uid,"alterId":aid,"encryption":scy}]}]},
        "streamSettings": stream
    }

def outbound_from_vless(link):
    u = urllib.parse.urlsplit(link)
    uid = u.username or ''
    host = u.hostname or ''
    port = int(u.port or 0)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    net = q.get('type') or q.get('network') or 'tcp'
    sec = q.get('security') or 'none'
    sni = q.get('sni') or q.get('serverName') or q.get('host') or ''
    flow = q.get('flow')
    path = q.get('path') or q.get('serviceName') or ''
    alpn = q.get('alpn')
    stream = {"network": net}
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        host_hdr = q.get('host') or q.get('Host')
        if host_hdr: ws["headers"]["Host"] = host_hdr
        stream["wsSettings"] = ws
    elif net == 'grpc':
        stream["grpcSettings"] = {"serviceName": path.lstrip("/") if path else ""}
    if sec != 'none':
        stream["security"] = sec
        if sec == 'tls':
            tls_settings = {}
            if sni: tls_settings["serverName"] = sni
            if alpn: tls_settings["alpn"] = alpn.split(',')
            stream["tlsSettings"] = tls_settings
        elif sec == 'reality':
            reality = {}
            if sni: reality["serverName"] = sni
            stream["realitySettings"] = reality
    user = {"id": uid, "encryption": q.get('encryption','none')}
    if flow: user["flow"] = flow
    return {
        "tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},
        "streamSettings": stream
    }

def outbound_from_trojan(link):
    u = urllib.parse.urlsplit(link)
    pwd = urllib.parse.unquote(u.username or '')
    host = u.hostname or ''
    port = int(u.port or 0)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    sni = q.get('sni') or q.get('peer') or q.get('host') or ''
    net = q.get('type') or 'tcp'
    path = q.get('path') or q.get('serviceName') or ''
    alpn = q.get('alpn')
    stream = {"network": net, "security":"tls"}
    tls_settings = {}
    if sni: tls_settings["serverName"] = sni
    if alpn: tls_settings["alpn"] = alpn.split(',')
    stream["tlsSettings"] = tls_settings
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        host_hdr = q.get('host') or q.get('Host') or sni
        if host_hdr: ws["headers"]["Host"] = host_hdr
        stream["wsSettings"] = ws
    elif net == 'grpc':
        stream["grpcSettings"] = {"serviceName": path.lstrip("/") if path else ""}
    return {
        "tag":"proxy","protocol":"trojan",
        "settings":{"servers":[{"address":host,"port":port,"password":pwd}]},
        "streamSettings": stream
    }

def try_json(raw):
    j = json.loads(raw)
    if isinstance(j, dict) and "outbounds" in j and isinstance(j["outbounds"], list) and j["outbounds"]:
        return j["outbounds"][0]
    if isinstance(j, dict) and "protocol" in j:
        return j
    raise ValueError("JSON provided but not an outbound or client config")

raw_strip = raw.strip()
if not raw_strip:
    sys.stderr.write("Empty input\n"); sys.exit(2)

try:
    if raw_strip.startswith("vmess://"):
        out = outbound_from_vmess(raw_strip)
    elif raw_strip.startswith("vless://"):
        out = outbound_from_vless(raw_strip)
    elif raw_strip.startswith("trojan://"):
        out = outbound_from_trojan(raw_strip)
    elif raw_strip.startswith("{"):
        out = try_json(raw_strip)
    else:
        raise ValueError("Unsupported input format")
except Exception as e:
    sys.stderr.write(f"Parse error: {e}\n"); sys.exit(2)

with open(out_path, "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
PY

  echo "$TMP_OUT"
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

  # Exclude upstream server if literal IPv4 (vmess/vless)
  SERVER_IP=$(jq -r '.settings.vnext[0].address // empty' "$OUTBOUND_FILE" 2>/dev/null || true)
  if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    iptables -t nat -A OUTPUT -d "$SERVER_IP"/32 -j RETURN
  fi
  # Exclude for trojan format too
  TROJAN_IP=$(jq -r '.settings.servers[0].address // empty' "$OUTBOUND_FILE" 2>/dev/null || true)
  if [[ "$TROJAN_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    iptables -t nat -A OUTPUT -d "$TROJAN_IP"/32 -j RETURN
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
  read -r -p "Enter destination TCP ports to tunnel (comma/ranges), or leave blank for ALL: " ONLY_PORTS

  echo
  echo "Paste your v2ray config/link (vmess://, vless://, trojan:// OR JSON). Press Ctrl+D when done:"
  USER_INPUT_FILE="$(mktemp)"
  cat > "$USER_INPUT_FILE"

  ensure_tools
  install_or_update_xray
  ensure_template

  # Convert user input to outbound.json
  OUTBOUND_JSON_FILE="$(to_outbound_json "$USER_INPUT_FILE")"

  build_config "$OUTBOUND_JSON_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_JSON_FILE" "$ONLY_PORTS"

  rm -f "$USER_INPUT_FILE" "$OUTBOUND_JSON_FILE"
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

if [[ -z "${MODE}" ]]; then
  interactive_menu
  exit 0
fi

if [[ "$MODE" == "rollback" ]]; then
  do_rollback
  exit 0
fi

if [[ "$MODE" == "setup" ]]; then
  CONFIG_INPUT="${2:-}"
  ONLY_PORTS=""
  if [[ $# -ge 3 && "${3:-}" == "--only-ports" ]]; then
    ONLY_PORTS="${4:-}"
  fi

  if [[ -z "$CONFIG_INPUT" ]]; then
    usage; echo; echo "Error: missing config input (link or JSON file)"; exit 1
  fi

  ensure_tools
  install_or_update_xray
  ensure_template

  # If the arg looks like a link, convert directly; otherwise treat as file path
  if [[ "$CONFIG_INPUT" =~ ^(vmess|vless|trojan):// ]]; then
    TMP_IN="$(mktemp)"; echo -n "$CONFIG_INPUT" > "$TMP_IN"
    OUTBOUND_JSON_FILE="$(to_outbound_json "$TMP_IN")"
    rm -f "$TMP_IN"
  else
    if [[ ! -f "$CONFIG_INPUT" ]]; then
      echo "File not found: $CONFIG_INPUT"; exit 1
    fi
    OUTBOUND_JSON_FILE="$(to_outbound_json "$CONFIG_INPUT")"
  fi

  build_config "$OUTBOUND_JSON_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_JSON_FILE" "$ONLY_PORTS"

  rm -f "$OUTBOUND_JSON_FILE"
  echo
  echo "[✓] Setup complete!"
  echo "Test:"
  echo "  curl -4 -x socks5h://127.0.0.1:1081 https://ifconfig.me"
  echo "  curl -4 https://ifconfig.me"
  exit 0
fi

usage; exit 1
