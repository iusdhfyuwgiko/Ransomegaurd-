#!/usr/bin/env bash
set -e

echo ""
echo " =========================================="
echo "  RansomGuard Early Warning System v2.4.1"
echo " =========================================="
echo ""

PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)

if [ -z "$PYTHON" ]; then
  echo " [ERROR] Python 3 not found. Install from https://python.org"
  exit 1
fi

echo " [1/3] Python found: $($PYTHON --version)"
echo " [2/3] Installing dependencies..."
$PYTHON -m pip install -r backend/requirements.txt -q

echo " [3/3] Starting server..."
echo ""
echo " Dashboard : http://localhost:8000"
echo " API Docs  : http://localhost:8000/docs"
echo " Press Ctrl+C to stop"
echo ""

cd backend
$PYTHON main.py
