#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -v
exec python3 runner.py --config "${1:-config.example.json}"
