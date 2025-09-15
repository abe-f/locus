#!/usr/bin/env bash
# Source this to set environment for Pin and building/running the pintool.
#   source ./source.sh

LOCUS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PIN_ROOT="${PIN_ROOT:-${LOCUS_DIR}/pin-3.31}"

if [[ ! -d "$PIN_ROOT" ]]; then
  echo "[locus] WARNING: PIN_ROOT ($PIN_ROOT) does not exist. Run ./install.sh" >&2
fi

export PATH="${PIN_ROOT}:${PATH}"
export LD_LIBRARY_PATH="${PIN_ROOT}/intel64/runtime:${LD_LIBRARY_PATH:-}"
echo "[locus] PIN_ROOT=${PIN_ROOT}"
