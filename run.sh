#!/usr/bin/env bash
set -e

echo "==================================================="
echo "  BaitDetect - Phishing Analysis System Launcher"
echo "==================================================="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.12+."
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment (venv)..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

echo "[*] Installing requirements..."
pip install -r requirements.txt --quiet

echo "[*] Launching BaitDetect on http://127.0.0.1:5000 ..."
if which xdg-open > /dev/null; then
  xdg-open http://127.0.0.1:5000 &
elif which open > /dev/null; then
  open http://127.0.0.1:5000 &
fi

python app.py
