#!/bin/bash

set -e

APP_NAME="edtunnel"
INSTALL_DIR="$HOME/$APP_NAME"
BIN_PATH="/usr/bin/$APP_NAME"
SOURCE_URL="https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/bind.go"

echo "[*] Creating project directory..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[*] Downloading source file..."
wget -q "$SOURCE_URL" -O main.go

echo "[*] Initializing Go module..."
go mod init edtunnel >/dev/null 2>&1 || true

echo "[*] Resolving dependencies..."
go mod tidy

echo "[*] Building binary..."
go build -o "$APP_NAME"

echo "[*] Installing binary to /usr/bin (requires sudo)..."
sudo mv "$APP_NAME" "$BIN_PATH"

echo
echo -e "\e[32m========================================="
echo -e "Installation successful."
echo -e "You should do next:"
echo -e "===> service edtunnel restart <==="
echo -e "=========================================\e[0m"
echo

read -p "Confirm restarting? (Y/N): " confirm

if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "[*] Restarting service..."
    sudo service edtunnel restart
    echo -e "\e[32mService restarted successfully.\e[0m"
else
    echo "Restart skipped. Live dangerously."
fi
