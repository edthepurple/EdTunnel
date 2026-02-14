#!/bin/bash
set -e

SERVICE_NAME="edtunnel"
SERVICE_PATH="/usr/bin/edtunnel"
WORK_DIR="/root/edtunnel"
GO_FILE="$WORK_DIR/def.go"
REPO_URL="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/def.go"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

XRAY_VERSION="v26.2.6"
XRAY_DIR="/usr/local/xray"
XRAY_BIN="/usr/bin/xray"
XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"

echo "[*] Detecting CPU architecture..."
ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
elif [[ "$ARCH" == "aarch64" ]]; then
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-arm64-v8a.zip"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "[*] Removing old services and binaries if they exist..."
systemctl stop edtunnel 2>/dev/null || true
systemctl disable edtunnel 2>/dev/null || true
systemctl stop xray 2>/dev/null || true
systemctl disable xray 2>/dev/null || true

rm -f "$SERVICE_FILE"
rm -f "$XRAY_SERVICE_FILE"
rm -f "$SERVICE_PATH"
rm -f "$XRAY_BIN"

systemctl daemon-reload

echo "[*] Setting up Go build directory..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[*] Downloading def.go..."
curl -fsSL "$REPO_URL" -o "$GO_FILE"

if ! command -v go >/dev/null 2>&1; then
    echo "[*] Installing Go..."
    apt update -y
    apt install -y snapd
    snap install go --classic
fi

echo "[*] Building edtunnel..."
go mod init edtunnel || true
go mod tidy
go build -o edtunnel
mv edtunnel "$SERVICE_PATH"
chmod +x "$SERVICE_PATH"
rm -rf "$WORK_DIR"

echo "[*] Installing unzip..."
apt update -y
apt install -y unzip curl

echo "[*] Downloading Xray..."
cd /tmp
curl -LO "$XRAY_URL"
unzip -o Xray-linux-*.zip
mv xray "$XRAY_BIN"
chmod +x "$XRAY_BIN"
rm -f Xray-linux-*.zip

echo "[*] Creating /usr/local/xray directory..."
mkdir -p "$XRAY_DIR"

echo ""
echo "server irane ya kharej?"
select LOCATION in "IRAN" "KHAREJ"; do
    case $LOCATION in
        IRAN)

            echo "[*] Downloading IRAN config..."
            curl -fsSL https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/lp-iran.conf -o ${XRAY_DIR}/config.json

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
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF

            break
            ;;

        KHAREJ)

            read -p "Enter IRAN server IP (ip:8080): " IRAN_HOST

            echo "[*] Downloading KHAREJ config..."
            curl -fsSL https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/lp-kharej.conf -o ${XRAY_DIR}/config.json

            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=EDTunnel VPN Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/edtunnel -mode vpn -host ${IRAN_HOST} -token lp -forward 42500,42200 -forwardudp 42300,42100
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

echo "[*] Creating Xray systemd service..."
cat > "$XRAY_SERVICE_FILE" <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/xray -c /usr/local/xray/config.json
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd..."
systemctl daemon-reload

echo "[*] Enabling services at startup..."
systemctl enable edtunnel
systemctl enable xray

echo "[*] Starting services..."
systemctl restart edtunnel
systemctl restart xray

echo "[*] Service status:"
systemctl status edtunnel --no-pager
systemctl status xray --no-pager

echo "[✓] Installation completed successfully."
