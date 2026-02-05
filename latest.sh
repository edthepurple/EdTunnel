#!/bin/bash

# Exit on any error
set -e

# Create temporary directory
mkdir -p edtunnel
cd edtunnel

# Initialize Go module
go mod init edtunnel

# Download the main.go file
curl -sSL https://raw.githubusercontent.com/edthepurple/EdTunnel/refs/heads/main/final.go -o main.go

# Tidy up dependencies
go mod tidy

# Build the application
go build

# Move the binary to /usr/bin (requires root)
sudo mv edtunnel /usr/bin/edtunnel

# Edit the systemd service file to add -tls flag
sudo sed -i 's|^\(ExecStart=.*\)$|\1 -tls|' /etc/systemd/system/edtunnel.service

# Reload systemd and restart service
sudo systemctl daemon-reload
sudo service edtunnel restart

# Go back to parent directory
cd ..

# Clean up the edtunnel folder
rm -rf edtunnel

echo "EdTunnel installation completed successfully!"
