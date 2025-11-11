#!/bin/bash
set -e

SERVICE_NAME="edtunnel"
SERVICE_PATH="/usr/bin/edtunnel"
WORK_DIR="/root/edtunnel"
GO_FILE="$WORK_DIR/main.go"
REPO_URL="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/simple.go"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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

# Step 3: Fetch source code (simple.go renamed to main.go)
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

# Step 6: Ask server type
echo ""
echo "server irane ya kharej?"
select LOCATION in "IRAN" "KHAREJ"; do
    case $LOCATION in
        IRAN)
            echo "[*] Configuring as IRAN (relay mode)..."
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel Relay Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode relay -port 8080 -token lp
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
        KHAREJ)
            read -p "Enter the IP address of the Iran server: " IRAN_IP
            echo "[*] Configuring as KHAREJ (VPN mode, connecting to $IRAN_IP)..."
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel Relay Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode vpn -host ${IRAN_IP}:8080 -token lp -forward 42500,42200 -forwardudp 42300,42100
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
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.ipv4.tcp_rmem = 4096 1048576 67108864
net.ipv4.tcp_wmem = 4096 1048576 67108864
net.ipv4.tcp_mem = 67108864 67108864 67108864
net.core.netdev_max_backlog = 50000
net.core.somaxconn = 8192
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
EOF

sysctl -p
echo "[✓] sysctl configuration applied successfully."
