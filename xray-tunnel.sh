#!/usr/bin/env bash
set -euo pipefail

TEMPLATE="/usr/local/etc/xray/config-template.json"
TARGET="/usr/local/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

# Cleanup function for temporary files
cleanup() {
    local exit_code=$?
    if [[ -n "${TMP_FILES:-}" ]]; then
        for file in $TMP_FILES; do
            [[ -f "$file" ]] && rm -f "$file"
        done
    fi
    exit $exit_code
}
trap cleanup EXIT INT TERM

# Store temp files for cleanup
TMP_FILES=""

# ========================= Colors & Visual Effects =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "============================================================="
    echo "                    🚀 XRAY TUNNEL"
    echo "                 Advanced Proxy Setup"
    echo "                  Created by: OmidZJ"
    echo "============================================================="
    echo -e "${NC}"
    
    # System information
    echo -e "${GRAY}System: $(uname -s) $(uname -r) • $(date +'%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${GRAY}User: $(whoami) • Working Directory: $(pwd)${NC}"
    echo
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script requires root privileges!"
        print_info "Please run with sudo: ${CYAN}sudo $0${NC}"
        exit 1
    fi
}

print_separator() {
    echo -e "${GRAY}$(printf '%.60s' "$(yes '=' | head -60 | tr -d '\n')")${NC}"
}

print_simple_box() {
    local title="$1"
    local content="$2"
    local color="${3:-$BLUE}"
    
    echo -e "\n${color}${BOLD}>> $title${NC}"
    echo -e "${color}$content${NC}\n"
}

print_box() {
    print_simple_box "$1" "$2" "$3"
}

show_spinner() {
    local pid=$1
    local message="$2"
    local i=0
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    
    while kill -0 $pid 2>/dev/null; do
        printf "\r${YELLOW}${spinner[$i]}${NC} %s..." "$message"
        i=$(((i+1) % ${#spinner[@]}))
        sleep 0.1
    done
    printf "\r${GREEN}✓${NC} %s... ${GREEN}Done${NC}\n" "$message"
}

print_success() {
    echo -e "${GREEN}  ✓${NC} $1"
}

print_error() {
    echo -e "${RED}  ✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}  ⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}  •${NC} $1"
}

print_step() {
    echo -e "\n${PURPLE}${BOLD}→${NC} $1"
}

usage() {
    print_header
    print_box "USAGE GUIDE" "$(cat <<'EOF'
Non-interactive mode:
  ./xray-tunnel.sh setup <config_input> [--only-ports "80,443"]
  
Config input options:
  • v2ray link: vmess://, vless://, trojan://, ss://
  • JSON file: full Xray/v2ray client config
  • JSON file: single outbound object

Interactive mode:
  ./xray-tunnel.sh
  
Commands:
  • setup     - Configure tunnel with proxy
  • rollback  - Remove tunnel and restore network
  • status    - Show current tunnel status
  • --help    - Display this help message
  
Options:
  --only-ports : Comma separated ports/ranges (e.g. 80,443,1000-2000)

Examples:
  ./xray-tunnel.sh setup "vmess://..." --only-ports "80,443"
  ./xray-tunnel.sh status
  ./xray-tunnel.sh rollback
EOF
)" "${BLUE}"
}

# ----------------- Enhanced Helper Functions -----------------
apply_redirect_rule() {
    local d="$1"
    [[ "$d" == *"-"* ]] && d="${d/-/:}"
    iptables -t nat -A OUTPUT -p tcp --dport "$d" -j REDIRECT --to-ports 12346
}

ensure_tools() {
    print_step "Checking required tools..."
    
    if ! command -v jq >/dev/null 2>&1; then
        print_info "Installing jq JSON processor..."
        (apt-get update -y && apt-get install -y jq) &
        show_spinner $! "Installing jq"
    else
        print_success "jq is already installed"
    fi
    
    if ! command -v python3 >/dev/null 2>&1; then
        print_info "Installing Python 3..."
        (apt-get update -y && apt-get install -y python3) &
        show_spinner $! "Installing Python3"
    else
        print_success "Python3 is already installed"
    fi
    
    echo
}

install_or_update_xray() {
    print_step "Installing/Updating Xray Core..."
    (bash <(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install >/dev/null 2>&1) &
    show_spinner $! "Downloading and installing Xray"
    echo
}

ensure_template() {
    if [[ ! -f "$TEMPLATE" ]]; then
        print_step "Creating Xray configuration template..."
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
        print_success "Configuration template created"
    else
        print_success "Configuration template already exists"
    fi
    echo
}

build_config() {
    local OUTBOUND_FILE="$1"
    print_step "Building final Xray configuration..."
    
    (jq --slurpfile ob "$OUTBOUND_FILE" '.outbounds[0] = $ob[0]' "$TEMPLATE" > "$TARGET") &
    show_spinner $! "Generating config.json"
    print_success "Configuration built successfully"
    echo
}

restart_xray() {
    print_step "Testing and starting Xray service..."
    
    print_info "Validating configuration..."
    if "$XRAY_BIN" run -test -config "$TARGET" >/dev/null 2>&1; then
        print_success "Configuration is valid"
    else
        print_error "Invalid configuration!"
        return 1
    fi
    
    print_info "Starting Xray service..."
    (systemctl restart xray && systemctl enable xray) &
    show_spinner $! "Starting service"
    print_success "Xray service is running"
    echo
}

flush_nat_output() {
    print_step "Cleaning previous iptables rules..."
    iptables -t nat -F OUTPUT >/dev/null 2>&1 || true
    print_success "Old rules cleared"
    echo
}

apply_iptables_rules() {
    local OUTBOUND_FILE="$1"
    local ONLY_PORTS="${2:-}"

    print_step "Configuring network traffic rules..."
    XRAY_UID=$(id -u nobody 2>/dev/null || echo 65534)

    print_info "Setting up traffic exceptions..."
    # exceptions
    iptables -t nat -A OUTPUT -m owner --uid-owner ${XRAY_UID} -j RETURN
    iptables -t nat -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    iptables -t nat -A OUTPUT -p tcp --sport 22 -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN
    iptables -t nat -A OUTPUT -d 127.0.0.1/32 -j RETURN
    iptables -t nat -A OUTPUT -d 127.0.0.53/32 -j RETURN

    # exclude upstream server if literal IPv4 (vnext/servers)
    print_info "Excluding proxy server from redirection..."
    for jqpath in '.settings.vnext[0].address' '.settings.servers[0].address'; do
        SERVER_IP="$(jq -r "$jqpath // empty" "$OUTBOUND_FILE" 2>/dev/null || true)"
        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            iptables -t nat -A OUTPUT -d "$SERVER_IP"/32 -j RETURN
            print_success "Excluded server IP: $SERVER_IP"
        fi
    done

    if [[ -n "$ONLY_PORTS" ]]; then
        print_info "Redirecting ONLY destination TCP ports: ${CYAN}$ONLY_PORTS${NC}"
        IFS=',' read -r -a PORT_ARR <<< "$ONLY_PORTS"
        for p in "${PORT_ARR[@]}"; do
            p="$(echo "$p" | xargs)"
            [[ -z "$p" ]] && continue
            apply_redirect_rule "$p"
            print_success "Port $p configured for tunneling"
        done
    else
        print_warning "Redirecting ALL destination TCP ports to tunnel"
        iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 12346
    fi

    print_info "Installing iptables-persistent to save rules..."
    (DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1) &
    show_spinner $! "Installing iptables-persistent"
    
    (netfilter-persistent save >/dev/null 2>&1) &
    show_spinner $! "Saving firewall rules"
    
    print_success "Network configuration completed"
    echo
}

do_rollback() {
    print_header
    print_box "ROLLBACK OPERATION" "Removing tunnel configuration and restoring network" "${RED}"
    
    print_step "Removing iptables rules..."
    iptables -t nat -F OUTPUT >/dev/null 2>&1 || true
    iptables -F >/dev/null 2>&1 || true
    iptables -t nat -F >/dev/null 2>&1 || true
    iptables -t mangle -F >/dev/null 2>&1 || true
    print_success "Firewall rules cleared"

    print_step "Stopping Xray service..."
    (systemctl stop xray >/dev/null 2>&1 || true) &
    show_spinner $! "Stopping service"
    (systemctl disable xray >/dev/null 2>&1 || true) &
    show_spinner $! "Disabling service"

    print_step "Saving clean network rules..."
    (netfilter-persistent save >/dev/null 2>&1 || true) &
    show_spinner $! "Saving configuration"

    print_box "ROLLBACK COMPLETE" "Network has been restored to default state" "${GREEN}"
}

show_status() {
    print_header
    print_box "SYSTEM STATUS" "Current tunnel configuration status" "${BLUE}"
    
    # Check Xray service status
    if systemctl is-active --quiet xray 2>/dev/null; then
        print_success "Xray service is running"
        
        # Check if configuration exists
        if [[ -f "$TARGET" ]]; then
            print_success "Configuration file exists: $TARGET"
            
            # Test configuration
            if "$XRAY_BIN" run -test -config "$TARGET" >/dev/null 2>&1; then
                print_success "Configuration is valid"
            else
                print_error "Configuration has errors"
            fi
        else
            print_warning "No configuration file found"
        fi
        
        # Check SOCKS proxy
        if ss -tlnp 2>/dev/null | grep -q ":1081"; then
            print_success "SOCKS5 proxy listening on port 1081"
        else
            print_warning "SOCKS5 proxy not detected"
        fi
        
        # Check transparent proxy
        if ss -tlnp 2>/dev/null | grep -q ":12346"; then
            print_success "Transparent proxy listening on port 12346"
        else
            print_warning "Transparent proxy not detected"
        fi
        
        # Check iptables rules
        if iptables -t nat -L OUTPUT 2>/dev/null | grep -q "REDIRECT"; then
            print_success "Iptables redirection rules are active"
        else
            print_warning "No iptables redirection rules found"
        fi
        
    else
        print_error "Xray service is not running"
        print_info "Run setup to configure the tunnel"
    fi
    
    print_box "QUICK TESTS" "Commands to test your tunnel" "${CYAN}"
    echo -e "Test SOCKS5 proxy:"
    echo -e "${GREEN}curl -x socks5h://127.0.0.1:1081 https://ifconfig.me${NC}"
    echo
    echo -e "Test transparent proxy:"
    echo -e "${GREEN}curl https://ifconfig.me${NC}"
    echo
}

show_progress_bar() {
    local duration=$1
    local message="$2"
    local progress=0
    local bar_length=25
    
    while [ $progress -le 100 ]; do
        local filled=$((progress * bar_length / 100))
        local empty=$((bar_length - filled))
        
        printf "\r${CYAN}$message ${NC}["
        printf "%*s" $filled | tr ' ' '='
        printf "%*s" $empty | tr ' ' '-'
        printf "] ${GREEN}%d%%${NC}" $progress
        
        progress=$((progress + 5))
        sleep 0.08
    done
    printf "\n"
}

# ---- Enhanced Converter: link/JSON -> outbound JSON ----
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
    print_header
    print_box "INTERACTIVE SETUP" "Configure your Xray tunnel step by step" "${PURPLE}"
    
    echo -e "${BOLD}${CYAN}Step 1: Port Configuration${NC}"
    echo -e "Configure which TCP ports should be tunneled through the proxy"
    echo
    echo -e "Examples:"
    echo -e "  ${GREEN}80,443${NC}           - Only HTTP and HTTPS"
    echo -e "  ${GREEN}1000-2000${NC}        - Port range from 1000 to 2000"  
    echo -e "  ${GREEN}80,443,1000-2000${NC} - Mixed ports and ranges"
    echo -e "  ${GREEN}[blank]${NC}          - ALL TCP ports (recommended)"
    echo
    read -r -p "$(echo -e "${YELLOW}→${NC} Enter ports (or press Enter for ALL): ")" ONLY_PORTS
    
    if [[ -z "$ONLY_PORTS" ]]; then
        echo -e "${GREEN}  ✓${NC} Selected: ALL TCP ports"
    else
        echo -e "${GREEN}  ✓${NC} Selected ports: ${CYAN}$ONLY_PORTS${NC}"
    fi
    echo
    
    echo -e "${BOLD}${CYAN}Step 2: Proxy Configuration${NC}"
    echo -e "Paste your proxy configuration (v2ray link or JSON)"
    echo
    echo -e "Supported formats:"
    echo -e "  ${GREEN}vmess://${NC}... (V2Ray VMess)"
    echo -e "  ${GREEN}vless://${NC}... (VLESS protocol)"
    echo -e "  ${GREEN}trojan://${NC}... (Trojan protocol)"
    echo -e "  ${GREEN}ss://${NC}... (Shadowsocks)"
    echo -e "  ${GREEN}JSON${NC} configuration file"
    echo
    echo -e "${YELLOW}→${NC} Paste your configuration and press ${BOLD}Ctrl+D${NC} when done:"
    echo

    TMP_IN="$(mktemp)"
    TMP_FILES="$TMP_FILES $TMP_IN"
    cat > "$TMP_IN"
    
    if [[ ! -s "$TMP_IN" ]]; then
        print_error "No configuration provided!"
        exit 1
    fi
    
    echo -e "\n${BOLD}${CYAN}Step 3: Setup Process${NC}"
    echo -e "Installing and configuring your tunnel..."
    echo

    ensure_tools
    install_or_update_xray
    ensure_template

    OUTBOUND_FILE="$(mktemp)"
    TMP_FILES="$TMP_FILES $OUTBOUND_FILE"
    print_step "Parsing configuration..."
    if ! convert_link_to_outbound "$TMP_IN" > "$OUTBOUND_FILE" 2>/dev/null; then
        print_error "Failed to parse configuration!"
        exit 1
    fi
    
    if [[ ! -s "$OUTBOUND_FILE" ]]; then
        print_error "Invalid configuration - no outbound generated!"
        exit 1
    fi
    
    print_success "Configuration parsed successfully"

    build_config "$OUTBOUND_FILE"
    restart_xray
    flush_nat_output
    apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"
    
    print_box "SETUP COMPLETE!" "$(cat <<EOF
Your Xray tunnel is now active!

SOCKS5 Proxy: 127.0.0.1:1081
Transparent Mode: Active $(if [[ -z "$ONLY_PORTS" ]]; then echo "(All TCP)"; else echo "($ONLY_PORTS)"; fi)

Test Commands:
• curl -x socks5h://127.0.0.1:1081 https://ifconfig.me
• curl https://ifconfig.me
EOF
)" "${GREEN}"
}

interactive_menu() {
    print_header
    
    echo -e "${BOLD}${WHITE}Select an option:${NC}\n"
    
    echo -e "  ${GREEN}1${NC}  ${BOLD}Setup Xray Tunnel${NC}"
    echo -e "     ${GRAY}Configure and start proxy tunnel${NC}"
    echo
    echo -e "  ${RED}2${NC}  ${BOLD}Rollback Configuration${NC}"
    echo -e "     ${GRAY}Remove tunnel and restore network${NC}"
    echo
    echo -e "  ${BLUE}3${NC}  ${BOLD}Show Status${NC}"
    echo -e "     ${GRAY}Display current tunnel status${NC}"
    echo
    echo -e "  ${YELLOW}4${NC}  ${BOLD}Show Help${NC}"
    echo -e "     ${GRAY}Display usage information${NC}"
    echo
    echo -e "  ${CYAN}q${NC}  ${BOLD}Quit${NC}"
    echo -e "     ${GRAY}Exit the program${NC}"
    echo
    
    read -r -p "$(echo -e "${PURPLE}→${NC} Your choice [1-4/q]: ")" CH
    echo
    
    case "$CH" in
        1) interactive_setup ;;
        2) 
            echo -e "${YELLOW}  ⚠ Warning:${NC} This will remove the tunnel configuration."
            read -r -p "$(echo -e "${RED}→${NC} Are you sure? [y/N]: ")" confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                do_rollback
            else
                echo -e "${CYAN}Operation cancelled.${NC}"
                exit 0
            fi
            ;;
        3) show_status ;;
        4) usage; exit 0 ;;
        q|Q) 
            echo -e "${CYAN}Goodbye!${NC}"
            exit 0 ;;
        *) 
            print_error "Invalid option: $CH"
            sleep 2
            interactive_menu
            ;;
    esac
}

# ----------------- Enhanced Entry Point -----------------
MODE="${1:-}"

# Always check for root privileges except for help
if [[ "$MODE" != "--help" && "$MODE" != "-h" ]]; then
    check_root
fi

if [[ -z "$MODE" ]]; then
    interactive_menu
    exit 0
fi

if [[ "$MODE" == "--help" || "$MODE" == "-h" ]]; then
    usage
    exit 0
fi

if [[ "$MODE" == "rollback" ]]; then
    do_rollback
    exit 0
fi

if [[ "$MODE" == "status" ]]; then
    show_status
    exit 0
fi

if [[ "$MODE" == "setup" ]]; then
    CONFIG_INPUT="${2:-}"
    ONLY_PORTS=""
    if [[ $# -ge 3 && "${3:-}" == "--only-ports" ]]; then
        ONLY_PORTS="${4:-}"
    fi
    if [[ -z "$CONFIG_INPUT" ]]; then
        print_header
        print_error "Missing configuration input!"
        usage
        exit 1
    fi

    print_header
    print_box "NON-INTERACTIVE SETUP" "Configuring tunnel with provided parameters" "${PURPLE}"

    ensure_tools
    install_or_update_xray
    ensure_template

    OUTBOUND_FILE="$(mktemp)"
    TMP_FILES="$TMP_FILES $OUTBOUND_FILE"
    if [[ "$CONFIG_INPUT" =~ ^(vmess|vless|trojan|ss):// ]]; then
        print_step "Processing proxy link..."
        TMP="$(mktemp)"
        TMP_FILES="$TMP_FILES $TMP"
        printf '%s' "$CONFIG_INPUT" > "$TMP"
        if ! convert_link_to_outbound "$TMP" > "$OUTBOUND_FILE" 2>/dev/null; then
            print_error "Failed to parse proxy link!"
            exit 1
        fi
        print_success "Proxy link parsed successfully"
    else
        if [[ ! -f "$CONFIG_INPUT" ]]; then
            print_error "Configuration file not found: $CONFIG_INPUT"
            exit 1
        fi
        print_step "Processing configuration file..."
        if ! convert_link_to_outbound "$CONFIG_INPUT" > "$OUTBOUND_FILE" 2>/dev/null; then
            print_error "Failed to parse configuration file!"
            exit 1
        fi
        print_success "Configuration file parsed successfully"
    fi
    
    if [[ ! -s "$OUTBOUND_FILE" ]]; then
        print_error "No valid configuration generated!"
        exit 1
    fi

    echo
    build_config "$OUTBOUND_FILE"
    restart_xray
    flush_nat_output
    apply_iptables_rules "$OUTBOUND_FILE" "$ONLY_PORTS"
    
    print_box "SETUP COMPLETE!" "$(cat <<EOF
Your Xray tunnel is now active!

SOCKS5 Proxy: 127.0.0.1:1081
Transparent Mode: Active $(if [[ -z "$ONLY_PORTS" ]]; then echo "(All TCP)"; else echo "($ONLY_PORTS)"; fi)

Test Commands:
• curl -x socks5h://127.0.0.1:1081 https://ifconfig.me
• curl -v http://portquiz.net:2020
EOF
)" "${GREEN}"
    exit 0
fi

print_header
print_error "Unknown command: $MODE"
usage
exit 1
