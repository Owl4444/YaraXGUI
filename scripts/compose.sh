#!/bin/sh
# Choose storage for the local shell platform; forward Compose arguments intact.
set -eu
YARAXGUI_CHECKOUT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$YARAXGUI_CHECKOUT"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        set -- -f compose.yaml -f deployment/compose.windows.yaml "$@"
        ;;
    *)
        set -- -f compose.yaml "$@"
        ;;
esac
exec docker compose --project-directory "$YARAXGUI_CHECKOUT" "$@"
