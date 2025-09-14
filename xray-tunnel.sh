#!/usr/bin/env bash
set -euo pipefail

TEMPLATE="/usr/local/etc/xray/config-template.json"
TARGET="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

usage() {
  cat <<'EOF'
Usage (non-interactive):
  xray-setup.sh setup <config_input> [--only-ports "80,443,8080,10000-10100"]
    - <config_input> can be:
        * a v2ray link: vmess://..., vless://..., trojan://..., ss://...
        * a JSON file: full Xray/v2ray client config (first outbound is used)
        * a JSON file: a single outbound object

  xray-setup.sh rollback

Interactive mode:
  Just run: xray-setup.sh
  - Choose: Setup Xray or Rollback
  - Enter ports to tunnel (blank = ALL TCP)
  - Paste your v2ray link/JSON (Ctrl+D to submit)

Notes:
  --only-ports : Comma separated, supports ranges like 10000-10100.
EOF
}

# ----------------- Helpers -----------------
apply_redirect_rule() {
  local d="$1"
  [[ "$d" == *"-"* ]] && d="${d/-/:}"
  iptables -t nat -A OUTPUT -p tcp --dport "$d" -j REDIRECT --to-ports 12346
}

ensure_tools() {
  command -v jq >/dev/null 2>&1 || { echo "[+] Installing jq ..."; apt-get update -y && apt-get install -y jq; }
  command -v python3 >/dev/null 2>&1 || { echo "[+] Installing python3 ..."; apt-get update -y && apt-get install -y python3; }
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

  # exceptions
  iptables -t nat -A OUTPUT -m owner --uid-owner ${XRAY_UID} -j RETURN
  iptables -t nat -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -t nat -A OUTPUT -p tcp --sport 22 -j RETURN
  iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.1/32 -j RETURN
  iptables -t nat -A OUTPUT -d 127.0.0.53/32 -j RETURN

  # exclude upstream server if literal IPv4 (vnext/servers)
  for jqpath in '.settings.vnext[0].address' '.settings.servers[0].address'; do
    SERVER_IP="$(jq -r "$jqpath // empty" "$OUTBOUND_FILE" 2>/dev/null || true)"
    if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      iptables -t nat -A OUTPUT -d "$SERVER_IP"/32 -j RETURN
    fi
  done

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

# ---- Converter: link/JSON -> outbound JSON (supports vmess/vless/trojan/ss) ----
convert_link_to_outbound() {
python3 - "$@" <<'PY'
import sys, base64, json, urllib.parse, os

def read_input(path=None):
    if path and os.path.isfile(path):
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return sys.stdin.read().strip()

raw = read_input(sys.argv[1] if len(sys.argv)>1 else None)
if not raw:
    print("Parse error: empty input", file=sys.stderr); sys.exit(2)

def urlunq(s): return urllib.parse.unquote(s)

def b64fix(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = (4 - len(s) % 4) % 4
    return s + ('=' * pad)

def d64(s): return base64.b64decode(b64fix(s)).decode('utf-8','ignore')

# ---------- builders ----------
def ob_vmess(link):
    b64 = link.split('://',1)[1]
    data = json.loads(d64(b64))
    add = data.get('add'); port = int(data.get('port',0) or 0)
    uid = data.get('id'); aid = int(data.get('aid',0) or 0)
    net = (data.get('net') or 'tcp').lower()
    host = data.get('host') or ''
    path = data.get('path') or ''
    tls  = (data.get('tls') or '').lower()
    sni  = data.get('sni') or data.get('host') or ''
    scy  = data.get('scy') or 'auto'
    stream = {"network": net}
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        if host: ws["headers"]["Host"] = host
        stream["wsSettings"] = ws
    elif net in ('grpc','gun'):
        stream["grpcSettings"] = {"serviceName": (path.lstrip('/') if path else '')}
    if tls in ('tls','reality'):
        stream["security"] = 'tls' if tls=='tls' else 'reality'
        key = "tlsSettings" if tls=='tls' else "realitySettings"
        s = {};  sni and s.setdefault("serverName", sni)
        stream[key] = s
    return {
      "tag":"proxy","protocol":"vmess",
      "settings":{"vnext":[{"address":add,"port":port,"users":[{"id":uid,"alterId":aid,"encryption":scy}]}]},
      "streamSettings": stream
    }

def ob_vless(link):
    u = urllib.parse.urlsplit(link)
    uid = u.username or ''
    host = u.hostname or ''
    port = int(u.port or 0)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    for k in list(q): q[k]=urlunq(q[k])
    net = (q.get('type') or q.get('network') or 'tcp').lower()
    sec = (q.get('security') or 'none').lower()
    sni = q.get('sni') or q.get('serverName') or q.get('host') or ''
    flow = q.get('flow')
    path = q.get('path') or q.get('serviceName') or ''
    alpn = q.get('alpn')
    enc  = q.get('encryption','none')
    stream = {"network": net}
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        host_hdr = q.get('host') or q.get('Host')
        if host_hdr: ws["headers"]["Host"] = host_hdr
        stream["wsSettings"] = ws
    elif net == 'grpc':
        stream["grpcSettings"] = {"serviceName": (path.lstrip('/') if path else '')}
    if sec != 'none':
        stream["security"] = sec
        if sec == 'tls':
            tls_settings = {}
            sni and tls_settings.setdefault("serverName", sni)
            if alpn: tls_settings["alpn"] = alpn.split(',')
            stream["tlsSettings"] = tls_settings
        elif sec == 'reality':
            if sni: stream["realitySettings"] = {"serverName": sni}
    user = {"id": uid, "encryption": enc}
    if flow: user["flow"] = flow
    return {
      "tag":"proxy","protocol":"vless",
      "settings":{"vnext":[{"address":host,"port":port,"users":[user]}]},
      "streamSettings": stream
    }

def ob_trojan(link):
    u = urllib.parse.urlsplit(link)
    pwd = urlunq(u.username or '')
    host = u.hostname or ''
    port = int(u.port or 0)
    q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    for k in list(q): q[k]=urlunq(q[k])
    sni = q.get('sni') or q.get('peer') or q.get('host') or ''
    net = (q.get('type') or 'tcp').lower()
    path = q.get('path') or q.get('serviceName') or ''
    alpn = q.get('alpn')
    stream = {"network": net, "security":"tls"}
    tls_settings = {}
    sni and tls_settings.setdefault("serverName", sni)
    if alpn: tls_settings["alpn"] = alpn.split(',')
    stream["tlsSettings"] = tls_settings
    if net == 'ws':
        ws = {"path": path or "/", "headers": {}}
        host_hdr = q.get('host') or q.get('Host') or sni
        if host_hdr: ws["headers"]["Host"] = host_hdr
        stream["wsSettings"] = ws
    elif net == 'grpc':
        stream["grpcSettings"] = {"serviceName": (path.lstrip('/') if path else '')}
    return {
      "tag":"proxy","protocol":"trojan",
      "settings":{"servers":[{"address":host,"port":port,"password":pwd}]},
      "streamSettings": stream
    }

def ob_ss(link):
    s = urlunq(link[5:])
    if '#' in s: s,_ = s.split('#',1)
    qpos = s.find('?')
    query = ''
    if qpos != -1:
        s, query = s[:qpos], s[qpos+1:]
    q = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    if 'plugin' in q: q['plugin'] = urlunq(q['plugin'])
    def try_dec(part):
        try: return d64(part)
        except Exception: return None
    creds, addr = None, None
    if '@' in s:
        first, rest = s.split('@',1)
        dec = try_dec(first)
        if dec and ':' in dec: creds, addr = dec, rest
        else: creds, addr = first, rest
    else:
        dec = try_dec(s)
        if dec and '@' in dec: creds, addr = dec.rsplit('@',1)
        else: raise ValueError("Invalid ss link")
    if not creds or ':' not in creds: raise ValueError("Invalid ss creds")
    method, password = creds.split(':',1)
    if not addr or ':' not in addr: raise ValueError("Invalid ss host:port")
    host, port = addr.split(':',1)
    port = int(port)
    stream = {}
    plugin = q.get('plugin')
    if plugin:
        parts = plugin.split(';')
        if parts and parts[0] in ('v2ray-plugin','xray-plugin'):
            opts = { (kv.split('=')[0]): (kv.split('=')[1] if '=' in kv else '1') for kv in parts[1:] }
            mode = (opts.get('mode') or opts.get('transport') or '').lower()
            if mode in ('websocket','ws') or ('path' in opts) or ('host' in opts):
                stream["network"] = "ws"
                ws = {"path": opts.get('path','/'), "headers": {}}
                if 'host' in opts: ws["headers"]["Host"] = opts['host']
                stream["wsSettings"] = ws
                if 'tls' in opts or opts.get('security') == 'tls':
                    stream["security"] = "tls"
                    tls_settings = {}
                    if 'host' in opts: tls_settings["serverName"] = opts['host']
                    stream["tlsSettings"] = tls_settings
    out = {
      "tag":"proxy","protocol":"shadowsocks",
      "settings":{"servers":[{"address":host,"port":port,"method":method,"password":password}]}
    }
    if stream: out["streamSettings"] = stream
    return out

def try_json(s):
    j = json.loads(s)
    if isinstance(j, dict) and "outbounds" in j and isinstance(j["outbounds"], list) and j["outbounds"]:
        return j["outbounds"][0]
    if isinstance(j, dict) and "protocol" in j:
        return j
    raise ValueError("JSON provided but not an outbound or client config")

s = raw.strip()
try:
    if s.startswith('{'):
        out = try_json(s)
    elif s.startswith('vmess://'):
        out = ob_vmess(s)
    elif s.startswith('vless://'):
        out = ob_vless(s)
    elif s.startswith('trojan://'):
        out = ob_trojan(s)
    elif s.startswith('ss://'):
        out = ob_ss(s)
    else:
        raise ValueError("Unsupported input format")
    print(json.dumps(out, ensure_ascii=False, indent=2))
except Exception as e:
    print("Parse error:", e, file=sys.stderr)
    sys.exit(2)
PY
}

interactive_setup() {
  echo "== Xray Tunnel • Interactive Setup =="
  echo
  read -r -p "Enter destination TCP ports to tunnel (comma/ranges), or leave blank for ALL: " ONLY_PORTS
  echo
  echo "Paste your v2ray link/JSON (vmess://, vless://, trojan://, ss:// OR JSON). Press Ctrl+D when done:"

  TMP_IN="$(mktemp)"
  cat > "$TMP_IN"

  ensure_tools
  install_or_update_xray
  ensure_template

  OUTBOUND_FILE="$(mktemp)"
  if ! convert_link_to_outbound "$TMP_IN" > "$OUTBOUND_FILE"; then
    echo "[-] Failed to parse link/JSON"
    rm -f "$TMP_IN" "$OUTBOUND_FILE"
    exit 1
  fi
  [[ -s "$OUTBOUND_FILE" ]] || { echo "[-] Empty outbound after conversion"; rm -f "$TMP_IN" "$OUTBOUND_FILE"; exit 1; }

  build_config "$OUTBOUND_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"

  rm -f "$TMP_IN" "$OUTBOUND_FILE"
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

# ----------------- Entry -----------------
MODE="${1:-}"

if [[ -z "$MODE" ]]; then
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

  OUTBOUND_FILE="$(mktemp)"
  if [[ "$CONFIG_INPUT" =~ ^(vmess|vless|trojan|ss):// ]]; then
    TMP="$(mktemp)"; printf '%s' "$CONFIG_INPUT" > "$TMP"
    convert_link_to_outbound "$TMP" > "$OUTBOUND_FILE" || { echo "[-] Conversion failed"; rm -f "$TMP"; exit 1; }
    rm -f "$TMP"
  else
    [[ -f "$CONFIG_INPUT" ]] || { echo "File not found: $CONFIG_INPUT"; exit 1; }
    convert_link_to_outbound "$CONFIG_INPUT" > "$OUTBOUND_FILE" || { echo "[-] Conversion failed"; exit 1; }
  fi
  [[ -s "$OUTBOUND_FILE" ]] || { echo "[-] Empty outbound after conversion"; exit 1; }

  build_config "$OUTBOUND_FILE"
  restart_xray
  flush_nat_output
  apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"

  rm -f "$OUTBOUND_FILE"
  echo
  echo "[✓] Setup complete!"
  echo "Test:"
  echo "  curl -4 -x socks5h://127.0.0.1:1081 https://ifconfig.me"
  echo "  curl -4 -v http://portquiz.net:2020"
  exit 0
fi

usage; exit 1
