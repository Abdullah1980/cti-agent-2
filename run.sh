#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "CTI Agent 2 - Startup"
echo "Project folder: $(pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python 3 was not found. Install Python 3.11 or newer, then run this file again."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating local Python environment..."
  "$PYTHON_BIN" -m venv .venv
fi

echo "Installing requirements..."
".venv/bin/python" -m pip install --upgrade pip
".venv/bin/python" -m pip install --no-cache-dir -r requirements.txt

if [ ! -f ".env" ]; then
  cp ".env.example" ".env"
  echo ""
  echo "A .env file was created in the project folder."
  echo "Open .env, add your API keys, save it, then run ./run.sh again."
  echo ""
  exit 0
fi

PORT="${CTI_AGENT_PORT:-8010}"
echo "Starting CTI Agent 2 at http://127.0.0.1:${PORT}"
".venv/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
