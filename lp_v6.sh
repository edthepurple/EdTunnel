#!/bin/bash
set -e

SERVICE_NAME="edtunnel"
SERVICE_PATH="/usr/bin/edtunnel"
WORK_DIR="/root/edtunnel"
GO_FILE="$WORK_DIR/main.go"
REPO_URL="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/v6ready.go"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# ---------------------------------------------------------------------------
# format_host: takes a single host entry (with or without port) and returns
#   a properly formatted host:port string.
#   - IPv6 bare address          → [addr]:8080
#   - IPv6 with port             → [addr]:port   (handles both [addr]:port and addr:port)
#   - IPv4 bare address          → addr:8080
#   - IPv4 with port             → addr:port
# ---------------------------------------------------------------------------
format_host() {
    local entry="$1"

    # Already bracketed with port: [addr]:port  — just return as-is
    if [[ "$entry" =~ ^\[.*\]:[0-9]+$ ]]; then
        echo "$entry"
        return
    fi

    # Bracketed without port: [addr]  — add default port
    if [[ "$entry" =~ ^\[.*\]$ ]]; then
        echo "${entry}:8080"
        return
    fi

    # Count colons to distinguish IPv6 from IPv4
    local colon_count
    colon_count=$(echo "$entry" | tr -cd ':' | wc -c)

    if (( colon_count >= 2 )); then
        # IPv6 bare address (no brackets, no port) — wrap and add default port
        echo "[${entry}]:8080"
    elif (( colon_count == 1 )); then
        # IPv4 with port already (e.g. 1.2.3.4:8080)
        echo "$entry"
    else
        # IPv4 bare address — add default port
        echo "${entry}:8080"
    fi
}

# ---------------------------------------------------------------------------
# format_host_list: processes a comma-separated list through format_host
# ---------------------------------------------------------------------------
format_host_list() {
    local input="$1"
    local result=""
    IFS=',' read -ra ENTRIES <<< "$input"
    for entry in "${ENTRIES[@]}"; do
        entry=$(echo "$entry" | xargs)          # trim whitespace
        [ -z "$entry" ] && continue
        local formatted
        formatted=$(format_host "$entry")
        if [ -z "$result" ]; then
            result="$formatted"
        else
            result="${result},${formatted}"
        fi
    done
    echo "$result"
}

# Step 1: Remove existing service and binary
echo "[*] Checking for existing service..."
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo "[*] Found service $SERVICE_NAME, stopping and removing it..."
    systemctl stop "$SERVICE_NAME" || true
    systemctl disable "$SERVICE_NAME" || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
else
    echo "[*] No systemd service named $SERVICE_NAME found."
fi

if [ -f "$SERVICE_PATH" ]; then
    echo "[*] Removing old binary at $SERVICE_PATH..."
    rm -f "$SERVICE_PATH"
fi

# Step 2: Setup work directory
echo "[*] Setting up work directory..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Step 3: Fetch source code (v6ready.go renamed to main.go)
echo "[*] Fetching source code..."
curl -fsSL "$REPO_URL" -o "$GO_FILE"

# Step 4: Install Go if needed
if ! command -v go >/dev/null 2>&1; then
    echo "[*] Go not found, checking for snap..."
    if ! command -v snap >/dev/null 2>&1; then
        echo "[*] Snap not found, installing..."
        apt update -y
        apt install -y snapd
    fi
    echo "[*] Installing Go via snap..."
    snap install go --classic
else
    echo "[*] Go is already installed."
fi

# Step 5: Build Go project
cd "$WORK_DIR"
echo "[*] Initializing Go module..."
go mod init edtunnel || true
echo "[*] Fetching Go dependencies..."
go mod tidy
echo "[*] Building binary..."
go build -o edtunnel
echo "[*] Moving binary to /usr/bin..."
mv -f edtunnel "$SERVICE_PATH"
echo "[*] Cleaning up..."
rm -rf "$WORK_DIR"

# Step 6: Ask server type (read from /dev/tty so it works under curl | bash)
echo ""
echo "server irane ya kharej?"
echo "  1) IRAN"
echo "  2) KHAREJ"

while true; do
    read -p "#? " CHOICE < /dev/tty
    case $CHOICE in
        1)
            echo "[*] Configuring as IRAN (relay mode)..."
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel Relay Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode relay -port 8080 -token lp -tls
Restart=always
RestartSec=5

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF
            break
            ;;
        2)
            read -p "Enter the IP address(es) of the Iran server (e.g., 1.2.3.4:8080 or 2001:db8::1, comma-separated): " IRAN_INPUT < /dev/tty

            IRAN_HOST=$(format_host_list "$IRAN_INPUT")

            echo "[*] Configuring as KHAREJ (VPN mode, connecting to $IRAN_HOST)..."
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel Relay Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode vpn -host ${IRAN_HOST} -token lp -forward 42500,42200 -forwardudp 42300,42100 -tls
Restart=always
RestartSec=5

# Resource limits
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF
            break
            ;;
        *)
            echo "Invalid selection. Choose 1 or 2."
            ;;
    esac
done

# Step 7: Reload systemd and start service
echo "[*] Reloading systemd..."
systemctl daemon-reload
echo "[*] Enabling and starting $SERVICE_NAME..."
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
echo "[*] Showing service status..."
systemctl status "$SERVICE_NAME" --no-pager

# Step 8: Apply sysctl optimizations
echo "[*] Applying optimized sysctl configuration..."
cat > /etc/sysctl.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
fs.file-max = 2097152
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_max_orphans = 262144
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p
echo "[✓] sysctl configuration applied successfully."
