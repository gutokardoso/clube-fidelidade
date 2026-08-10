#!/usr/bin/env bash
set -e
python3 server.py --host 0.0.0.0 --port "${PORT:-8000}"
