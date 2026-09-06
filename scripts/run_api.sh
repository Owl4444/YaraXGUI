#!/bin/sh
# Use the selected environment's Python; keep credentials in the environment.
set -eu
YARAXGUI_CHECKOUT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$YARAXGUI_CHECKOUT"
exec "${YARAXGUI_PYTHON:-python3}" -m api.server "$@"
