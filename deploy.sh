#!/bin/bash
set -e

cd "$(dirname "$0")"

# Load secrets from environment (set in ~/.profile or passed by CI)
if [ -z "$KALLIX_SMTP_PASSWORD" ]; then
    echo "WARNING: KALLIX_SMTP_PASSWORD is not set — password reset emails will not work"
fi

echo "[deploy] Pulling latest..."
git pull origin main

echo "[deploy] Building backend..."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build build --parallel "$(nproc)"

echo "[deploy] Building frontend..."
cd frontend && npm ci --silent && npm run build
cd ..

echo "[deploy] Restarting outpost service..."
sudo systemctl restart outpost.service

sleep 2
if systemctl is-active --quiet outpost.service; then
    echo "[deploy] Done. Outpost is running."
else
    echo "[deploy] ERROR: outpost.service failed to start. Check: journalctl -u outpost -n 50"
    exit 1
fi
