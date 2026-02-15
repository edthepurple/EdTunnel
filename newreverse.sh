#!/bin/bash
set -e

SERVICE_NAME="edtunnel"
SERVICE_PATH="/usr/bin/edtunnel"
WORK_DIR="/root/edtunnel"

GO_MAIN="$WORK_DIR/newreverse.go"
GO_SOCKOPT="$WORK_DIR/sockopt_unix.go"

REPO_MAIN="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/newreverse.go"
REPO_SOCKOPT="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/sockopt_unix.go"
REPO_VENDOR="https://github.com/edthepurple/EdTunnel/raw/refs/heads/main/vendor.zip"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

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

echo "[*] Preparing work directory..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[*] Downloading source files..."
curl -fsSL "$REPO_MAIN" -o "$GO_MAIN"
curl -fsSL "$REPO_SOCKOPT" -o "$GO_SOCKOPT"

echo "[*] Downloading vendor.zip..."
curl -fsSL "$REPO_VENDOR" -o vendor.zip

echo "[*] Installing unzip if missing..."
if ! command -v unzip >/dev/null 2>&1; then
    apt update -y
    apt install -y unzip
fi

echo "[*] Extracting vendor directory..."
unzip -q vendor.zip
rm -f vendor.zip

echo "[*] Installing Go if needed..."
if ! command -v go >/dev/null 2>&1; then
    if ! command -v snap >/dev/null 2>&1; then
        apt update -y
        apt install -y snapd
    fi
    snap install go --classic
fi

echo "[*] Initializing module..."
go mod init edtunnel || true

echo "[*] Building using vendored dependencies..."
GOFLAGS="-mod=vendor" go build -o edtunnel newreverse.go sockopt_unix.go

mv -f edtunnel "$SERVICE_PATH"
chmod +x "$SERVICE_PATH"

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
