#!/usr/bin/env bash
# S5Core VPN Proxy — route ALL system TCP and UDP through obfuscated tunnel using tun2socks.
#
# Usage:
#   sudo ./vpn_test.sh start    — enable transparent proxy
#   sudo ./vpn_test.sh stop     — disable and restore direct connection
#   sudo ./vpn_test.sh status   — show current state

set -euo pipefail

# ============ CONFIG ============
SERVER_IP="YOUR_VPS_IP"
OBFS_PORT="1443"
OBFS_PSK="YOUR_32_BYTE_PSK"
OBFS_MAX_PADDING="256"
OBFS_MTU="1400"

PROXY_USER="your_username"
PROXY_PASS="your_password"

S5CLIENT_BIN="./s5client"              # Path to s5client binary
S5CLIENT_LISTEN="127.0.0.1:1080"       # s5client local SOCKS5

TUN_NAME="tun0"
TUN_IP="198.18.0.1"
TUN_NET="198.18.0.0/15"

TUN2SOCKS_BIN="${HOME}/go/bin/tun2socks"  # Or the path where you installed tun2socks
TUN2SOCKS_PID="/tmp/s5core_tun2socks.pid"
S5CLIENT_PID="/tmp/s5core_s5client.pid"
# ================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: Run with sudo${NC}"
        exit 1
    fi
}

check_deps() {
    if ! command -v ip &>/dev/null; then
        echo -e "${RED}ERROR: 'ip' command not found.${NC}"
        exit 1
    fi

    if [ ! -f "$S5CLIENT_BIN" ]; then
        echo -e "${RED}ERROR: s5client binary not found at '$S5CLIENT_BIN'${NC}"
        echo "Build it: go build -o s5client ./cmd/s5client/"
        exit 1
    fi
    
    if [ ! -f "$TUN2SOCKS_BIN" ]; then
        echo -e "${RED}ERROR: tun2socks binary not found at '$TUN2SOCKS_BIN'${NC}"
        echo "Install it: go install github.com/xjasonlyu/tun2socks/v2@latest"
        exit 1
    fi
}

start_s5client() {
    if [ -f "$S5CLIENT_PID" ] && kill -0 "$(cat "$S5CLIENT_PID")" 2>/dev/null; then
        echo -e "${YELLOW}s5client already running (PID: $(cat "$S5CLIENT_PID"))${NC}"
        return
    fi

    echo "Starting s5client..."
    SERVER_ADDR="${SERVER_IP}:${OBFS_PORT}" \
    OBFS_PSK="${OBFS_PSK}" \
    OBFS_MAX_PADDING="${OBFS_MAX_PADDING}" \
    OBFS_MTU="${OBFS_MTU}" \
    PROXY_USER="${PROXY_USER}" \
    PROXY_PASS="${PROXY_PASS}" \
    nohup "$S5CLIENT_BIN" > /tmp/s5client.log 2>&1 &

    echo $! > "$S5CLIENT_PID"
    sleep 1

    if kill -0 "$(cat "$S5CLIENT_PID")" 2>/dev/null; then
        echo -e "${GREEN}s5client started (PID: $(cat "$S5CLIENT_PID"))${NC}"
    else
        echo -e "${RED}s5client failed to start. Check /tmp/s5client.log${NC}"
        exit 1
    fi
}

start_tun2socks() {
    if [ -f "$TUN2SOCKS_PID" ] && kill -0 "$(cat "$TUN2SOCKS_PID")" 2>/dev/null; then
        echo -e "${YELLOW}tun2socks already running${NC}"
        return
    fi

    # Create TUN device
    ip tuntap add mode tun dev "$TUN_NAME" 2>/dev/null || true
    ip addr add "$TUN_IP" dev "$TUN_NAME" 2>/dev/null || true
    ip link set dev "$TUN_NAME" up

    echo "Starting tun2socks..."
    nohup "$TUN2SOCKS_BIN" -device "$TUN_NAME" -proxy "socks5://${S5CLIENT_LISTEN}" > /tmp/tun2socks.log 2>&1 &
    echo $! > "$TUN2SOCKS_PID"
    sleep 1

    if kill -0 "$(cat "$TUN2SOCKS_PID")" 2>/dev/null; then
        echo -e "${GREEN}tun2socks started (PID: $(cat "$TUN2SOCKS_PID"))${NC}"
    else
        echo -e "${RED}tun2socks failed. Check /tmp/tun2socks.log${NC}"
        exit 1
    fi
}

setup_routing() {
    echo "Configuring routing..."
    
    # Save default gateway
    DEFAULT_GW=$(ip route show default | awk '/default/ {print $3}')
    DEFAULT_IF=$(ip route show default | awk '/default/ {print $5}')
    
    if [ -z "$DEFAULT_GW" ]; then
         echo -e "${RED}Could not determine default gateway.${NC}"
         exit 1
    fi
    echo "$DEFAULT_GW" > /tmp/s5core_default_gw
    echo "$DEFAULT_IF" > /tmp/s5core_default_if

    # 1. Route to S5Core server via the original default gateway
    ip route add "${SERVER_IP}" via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
    
    # 2. Add specific routes for typical local networks so they don't go into TUN
    ip route add 10.0.0.0/8 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
    ip route add 172.16.0.0/12 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
    ip route add 192.168.0.0/16 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true

    # 3. Create two /1 routes to override the default route without deleting it
    ip route add 0.0.0.0/1 dev "$TUN_NAME"
    ip route add 128.0.0.0/1 dev "$TUN_NAME"

    echo -e "${GREEN}Routing configured${NC}"
}

teardown_routing() {
    echo "Restoring routing..."
    
    if [ -f /tmp/s5core_default_gw ]; then
        DEFAULT_GW=$(cat /tmp/s5core_default_gw)
        DEFAULT_IF=$(cat /tmp/s5core_default_if)
        
        ip route del 0.0.0.0/1 dev "$TUN_NAME" 2>/dev/null || true
        ip route del 128.0.0.0/1 dev "$TUN_NAME" 2>/dev/null || true
        
        ip route del "${SERVER_IP}" via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
        ip route del 10.0.0.0/8 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
        ip route del 172.16.0.0/12 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
        ip route del 192.168.0.0/16 via "$DEFAULT_GW" dev "$DEFAULT_IF" 2>/dev/null || true
        
        rm -f /tmp/s5core_default_gw /tmp/s5core_default_if
    fi
    
    ip link delete "$TUN_NAME" 2>/dev/null || true

    echo -e "${GREEN}Routing restored${NC}"
}

stop_processes() {
    if [ -f "$TUN2SOCKS_PID" ]; then
        echo "Stopping tun2socks..."
        kill "$(cat "$TUN2SOCKS_PID")" 2>/dev/null || true
        rm -f "$TUN2SOCKS_PID"
    fi

    if [ -f "$S5CLIENT_PID" ]; then
        echo "Stopping s5client..."
        kill "$(cat "$S5CLIENT_PID")" 2>/dev/null || true
        rm -f "$S5CLIENT_PID"
    fi

    echo -e "${GREEN}Processes stopped${NC}"
}

do_start() {
    check_root
    check_deps

    echo "========================================"
    echo "  Starting S5Core VPN (tun2socks)"
    echo "  ALL Traffic (TCP+UDP) → tun0 → s5client → [obfs] → ${SERVER_IP}:${OBFS_PORT}"
    echo "========================================"
    echo ""

    start_s5client
    start_tun2socks
    setup_routing

    echo ""
    echo -e "${GREEN}✅ VPN is ACTIVE${NC}"
    echo -e "   All system traffic (including UDP/DNS) goes through obfuscated tunnel."
    echo -e "   Zero WebRTC leaks."
    echo ""
    echo "   To verify IP: curl https://ifconfig.me"
    echo "   To stop:      sudo $0 stop"
}

do_stop() {
    check_root

    echo "========================================"
    echo "  Stopping S5Core VPN"
    echo "========================================"
    echo ""

    teardown_routing
    stop_processes

    echo ""
    echo -e "${GREEN}✅ Direct connection restored${NC}"
}

do_status() {
    echo "=== S5Core VPN Status ==="

    if [ -f "$S5CLIENT_PID" ] && kill -0 "$(cat "$S5CLIENT_PID")" 2>/dev/null; then
        echo -e "s5client:   ${GREEN}RUNNING${NC} (PID: $(cat "$S5CLIENT_PID"))"
    else
        echo -e "s5client:   ${RED}STOPPED${NC}"
    fi

    if [ -f "$TUN2SOCKS_PID" ] && kill -0 "$(cat "$TUN2SOCKS_PID")" 2>/dev/null; then
        echo -e "tun2socks:  ${GREEN}RUNNING${NC} (PID: $(cat "$TUN2SOCKS_PID"))"
    else
        echo -e "tun2socks:  ${RED}STOPPED${NC}"
    fi

    if ip link show "$TUN_NAME" &>/dev/null; then
        echo -e "interface:  ${GREEN}ACTIVE${NC} ($TUN_NAME)"
    else
        echo -e "interface:  ${RED}INACTIVE${NC}"
    fi

    echo ""
    echo "Current external IP:"
    # Use timeout to avoid hanging if routing is broken
    timeout 5 curl -s https://ifconfig.me 2>/dev/null || echo "(could not determine)"
    echo ""
}

case "${1:-}" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)
        echo "Usage: sudo $0 {start|stop|status}"
        exit 1
        ;;
esac
