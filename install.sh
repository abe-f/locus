#!/usr/bin/env bash
# Install Intel Pin 3.31 into locus/pin-3.31 (idempotent) with downloads cached in build/
set -euo pipefail
cd "$(dirname "$0")"

PIN_VER="3.31"
PIN_BUILD="98869"
PIN_HASH="gfa6f126a8"
PIN_TARBALL="pin-external-${PIN_VER}-${PIN_BUILD}-${PIN_HASH}-gcc-linux.tar.gz"
PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_TARBALL}"

PIN_DIR_FINAL="pin-3.31"
PIN_DIR_EXTRACTED="pin-external-${PIN_VER}-${PIN_BUILD}-${PIN_HASH}-gcc-linux"
CACHE_DIR="build/cache"
mkdir -p "${CACHE_DIR}"

if [[ -d "${PIN_DIR_FINAL}" ]]; then
  echo "[locus] ${PIN_DIR_FINAL} already present."
else
  echo "[locus] Downloading Intel Pin ${PIN_VER} ..."
  if [[ ! -f "${CACHE_DIR}/${PIN_TARBALL}" ]]; then
    curl -L --fail -o "${CACHE_DIR}/${PIN_TARBALL}" "${PIN_URL}"
  else
    echo "[locus] Tarball already present: ${CACHE_DIR}/${PIN_TARBALL}"
  fi

  echo "[locus] Unpacking ${PIN_TARBALL} ..."
  tar -C "${CACHE_DIR}" -xzf "${CACHE_DIR}/${PIN_TARBALL}"

  if [[ -d "${CACHE_DIR}/${PIN_DIR_EXTRACTED}" ]]; then
    mv -f "${CACHE_DIR}/${PIN_DIR_EXTRACTED}" "${PIN_DIR_FINAL}"
  else
    echo "[locus] ERROR: expected directory ${CACHE_DIR}/${PIN_DIR_EXTRACTED} not found after extract." >&2
    exit 1
  fi
fi

mkdir -p outputs

cat <<EOF

[locus] Intel Pin installed at: $(pwd)/${PIN_DIR_FINAL}

Next:
  source ./source.sh
  ./build.sh
EOF
