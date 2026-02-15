#!/bin/bash
set -e

SERVICE_NAME="edtunnel"
SERVICE_PATH="/usr/bin/edtunnel"
WORK_DIR="/root/edtunnel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

AMD64_URL="https://github.com/edthepurple/EdTunnel/raw/refs/heads/main/edtunnel-linux-amd64"
ARM64_URL="https://github.com/edthepurple/EdTunnel/raw/refs/heads/main/edtunnel-linux-arm64"

echo "[*] Detecting CPU architecture..."
ARCH=$(uname -m)

case "$ARCH" in
    x86_64)
        DOWNLOAD_URL="$AMD64_URL"
        echo "[*] Detected amd64 architecture."
        ;;
    aarch64|arm64)
        DOWNLOAD_URL="$ARM64_URL"
        echo "[*] Detected arm64 architecture."
        ;;
    *)
        echo "[!] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "[*] Removing old service if exists..."
if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    systemctl stop "$SERVICE_NAME" || true
    systemctl disable "$SERVICE_NAME" || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
fi

if [ -f "$SERVICE_PATH" ]; then
    rm -f "$SERVICE_PATH"
fi

echo "[*] Downloading edtunnel binary..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

curl -fsSL "$DOWNLOAD_URL" -o edtunnel

chmod +x edtunnel
mv -f edtunnel "$SERVICE_PATH"
rm -rf "$WORK_DIR"

echo ""
echo "server irane ya kharej?"

select LOCATION in "IRAN" "KHAREJ"; do
    case $LOCATION in
        IRAN)
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel Relay Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode relay -port 8080 -token edwin -tls -padding
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF
            break
            ;;
        KHAREJ)
            read -p "Enter IRAN server IP (example: 87.248.142.12): " IRAN_HOST
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel VPN Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode vpn -host ${IRAN_HOST} -port 8080 -forward 8443,8443 -forwardudp 8443,8443 -token edwin -tls -insecure -sni dash.cloudflare.com
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF
            break
            ;;
        *)
            echo "Invalid selection."
            ;;
    esac
done

echo "[*] Reloading systemd..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
systemctl status "$SERVICE_NAME" --no-pager

echo "[✓] Installation complete."
