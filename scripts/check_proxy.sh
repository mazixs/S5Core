#!/usr/bin/env bash
# S5Core Proxy Health Check Script
# Add your credentials below before running.

set -euo pipefail

# ============ CONFIG ============
SERVER_IP="YOUR_VPS_IP"
PROXY_PORT="1080"
OBFS_PORT="1443"

PROXY_USER="your_username"
PROXY_PASS="your_password"
OBFS_PSK="YOUR_32_BYTE_PSK"
# ================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; }
fail() { echo -e "${RED}❌ FAIL${NC}: $1"; }
info() { echo -e "${YELLOW}ℹ️  INFO${NC}: $1"; }

echo "========================================"
echo "  S5Core Proxy Check"
echo "  Server: ${SERVER_IP}"
echo "========================================"
echo ""

# 1. TCP connectivity check
echo "--- 1. TCP Connectivity ---"
if timeout 5 bash -c "echo >/dev/tcp/${SERVER_IP}/${PROXY_PORT}" 2>/dev/null; then
    pass "Port ${PROXY_PORT} (plain SOCKS5) is reachable"
else
    fail "Port ${PROXY_PORT} is NOT reachable"
fi

if timeout 5 bash -c "echo >/dev/tcp/${SERVER_IP}/${OBFS_PORT}" 2>/dev/null; then
    pass "Port ${OBFS_PORT} (obfuscated) is reachable"
else
    fail "Port ${OBFS_PORT} is NOT reachable"
fi
echo ""

# 2. Plain SOCKS5 with auth
echo "--- 2. Plain SOCKS5 (port ${PROXY_PORT}) ---"
PLAIN_IP=$(curl -s --max-time 10 --socks5 "${SERVER_IP}:${PROXY_PORT}" -U "${PROXY_USER}:${PROXY_PASS}" https://ifconfig.me 2>/dev/null || true)
if [ -n "$PLAIN_IP" ]; then
    pass "Plain SOCKS5 works! Exit IP: ${PLAIN_IP}"
else
    fail "Plain SOCKS5 connection failed"
fi
echo ""

# 3. Plain SOCKS5 — full ipinfo
echo "--- 3. GeoIP Info (plain) ---"
IPINFO=$(curl -s --max-time 10 --socks5 "${SERVER_IP}:${PROXY_PORT}" -U "${PROXY_USER}:${PROXY_PASS}" https://ipinfo.io 2>/dev/null || true)
if [ -n "$IPINFO" ]; then
    pass "ipinfo.io response:"
    echo "$IPINFO" | head -20
else
    fail "Could not reach ipinfo.io"
fi
echo ""

# 4. Health endpoint
echo "--- 4. Health Endpoint ---"
HEALTH=$(curl -s --max-time 5 "http://${SERVER_IP}:8080/health" 2>/dev/null || true)
if [ -n "$HEALTH" ]; then
    pass "Health endpoint: ${HEALTH}"
else
    info "Health endpoint not reachable (port 8080 may not be exposed)"
fi
echo ""

# 5. Metrics endpoint
echo "--- 5. Metrics Endpoint ---"
METRICS=$(curl -s --max-time 5 "http://${SERVER_IP}:8080/metrics" 2>/dev/null | head -5 || true)
if [ -n "$METRICS" ]; then
    pass "Metrics endpoint reachable. First 5 lines:"
    echo "$METRICS"
else
    info "Metrics endpoint not reachable (port 8080 may not be exposed)"
fi
echo ""

# 6. Obfuscation port check (can't fully test without s5client binary)
echo "--- 6. Obfuscation Port (${OBFS_PORT}) ---"
info "Full obfs test requires s5client binary."
info "To test manually:"
echo ""
echo "  SERVER_ADDR=${SERVER_IP}:${OBFS_PORT} \\"
echo "  OBFS_PSK=${OBFS_PSK} \\"
echo "  ./s5client"
echo ""
echo "  # Then in another terminal:"
echo "  curl --socks5 127.0.0.1:1080 https://ifconfig.me"
echo ""

# 7. DNS resolution through proxy
echo "--- 7. DNS Resolution Through Proxy ---"
DNS_TEST=$(curl -s --max-time 10 --socks5-hostname "${SERVER_IP}:${PROXY_PORT}" -U "${PROXY_USER}:${PROXY_PASS}" https://dns.google/resolve?name=example.com 2>/dev/null || true)
if [ -n "$DNS_TEST" ]; then
    pass "DNS resolution through proxy works"
else
    fail "DNS resolution through proxy failed"
fi
echo ""

echo "========================================"
echo "  Check complete"
echo "========================================"
