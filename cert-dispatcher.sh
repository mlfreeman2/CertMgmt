#!/bin/sh
# Compatibility launcher; implementation lives in the certmgmt Python package.
CERTMGMT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "${CERTMGMT_PYTHON:-python3}" "$CERTMGMT_ROOT/certmgmt-launch.py" cert-dispatcher.sh "$@"
