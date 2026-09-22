#!/usr/bin/env bash
# Create a matching server/client pair without replacing existing credentials.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 HOST:PORT (example: $0 server.example.com:28479)" >&2
    exit 1
fi
server_addr=$1
address_pattern='^(\[[a-fA-F0-9:]+\]|[a-zA-Z0-9._-]+):([0-9]+)$'
if [[ ! $server_addr =~ $address_pattern ]]; then
    echo 'Expected a hostname, IPv4 address or [IPv6] address followed by :PORT.' >&2
    exit 1
fi
port=${BASH_REMATCH[2]}
if [[ ${#port} -gt 5 ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    echo 'Port must be between 1 and 65535.' >&2
    exit 1
fi
port=$((10#$port))
for file in .env .env.client; do
    if [[ -e $file || -L $file ]]; then
        echo "Refusing to replace $file. Keep existing credentials when updating." >&2
        exit 1
    fi
done
command -v openssl >/dev/null || { echo 'Install OpenSSL to generate credentials.' >&2; exit 1; }
umask 077
tmp_dir=$(mktemp -d ./.s5core-init.XXXXXX)
trap 'rm -rf "$tmp_dir"' EXIT
password=$(openssl rand -hex 24)
psk=$(openssl rand -base64 24)
sed -e "s|^PROXY_PASSWORD=.*|PROXY_PASSWORD='$password'|" \
    -e "s|^OBFS_PSK=.*|OBFS_PSK='$psk'|" \
    -e "s|^OBFS_PORT=.*|OBFS_PORT=$port|" \
    .env.example > "$tmp_dir/server"
sed -e "s|^PROXY_PASS=.*|PROXY_PASS='$password'|" \
    -e "s|^OBFS_PSK=.*|OBFS_PSK='$psk'|" \
    -e "s|^SERVER_ADDR=.*|SERVER_ADDR='$server_addr'|" \
    .env.client.example > "$tmp_dir/client"
# Hard links publish complete files and fail if a destination appeared meanwhile.
ln "$tmp_dir/server" .env
if ! ln "$tmp_dir/client" .env.client; then
    rm .env
    exit 1
fi
printf 'Created .env and .env.client (mode 600). Secrets were not printed.\n'
printf 'Server: docker compose up -d\nClient: securely copy .env.client to the client machine.\n'
