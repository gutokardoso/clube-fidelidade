#!/usr/bin/env sh
set -eu
python3 server.py --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
