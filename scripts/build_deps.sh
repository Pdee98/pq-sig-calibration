#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="$ROOT/third_party"
PREFIX="$TP/install"
CACHE="$TP/cache"
WORK_ROOT="${PQ_CAL_BUILD_ROOT:-${RUNNER_TEMP:-/tmp}/pq-sig-calibration-build-${UID}}"
SRC="$WORK_ROOT/src"
BUILD="$WORK_ROOT/build"
OPENSSL_VERSION=3.5.5
OPENSSL_SHA256=b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89
LIBOQS_VERSION=0.16.0
LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
LIBOQS_SHA256=162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae

mkdir -p "$CACHE" "$SRC" "$BUILD" "$PREFIX"
fetch() { local url=$1 out=$2 hash=$3; if [[ ! -f $out ]]; then curl -L --fail --retry 3 -o "$out" "$url"; fi; echo "$hash  $out" | sha256sum -c -; }

fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
  "$CACHE/openssl-${OPENSSL_VERSION}.tar.gz" "$OPENSSL_SHA256"
fetch "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" \
  "$CACHE/liboqs-${LIBOQS_VERSION}.tar.gz" "$LIBOQS_SHA256"

if [[ ! -x "$PREFIX/bin/openssl" ]] || ! "$PREFIX/bin/openssl" version | grep -q "OpenSSL ${OPENSSL_VERSION}"; then
  rm -rf "$SRC/openssl-${OPENSSL_VERSION}" "$BUILD/openssl"
  tar -xzf "$CACHE/openssl-${OPENSSL_VERSION}.tar.gz" -C "$SRC"
  mkdir -p "$BUILD/openssl"
  pushd "$SRC/openssl-${OPENSSL_VERSION}" >/dev/null
  case "$(uname -m)" in x86_64) target=linux-x86_64;; aarch64|arm64) target=linux-aarch64;; *) echo "Unsupported architecture" >&2; exit 2;; esac
  ./Configure "$target" --prefix="$PREFIX" --openssldir="$PREFIX/ssl" shared no-tests -O3
  make -j"$(nproc)"
  make install_sw
  popd >/dev/null
fi

rm -rf "$SRC/liboqs-${LIBOQS_VERSION}" "$BUILD/liboqs"
tar -xzf "$CACHE/liboqs-${LIBOQS_VERSION}.tar.gz" -C "$SRC"
mkdir -p "$TP/kat"
cp "$SRC/liboqs-${LIBOQS_VERSION}/tests/KATs/sig_stfl/kats.json" "$TP/kat/kats.json"
if [[ ! -f "$PREFIX/lib/liboqs.so" ]]; then
cmake -S "$SRC/liboqs-${LIBOQS_VERSION}" -B "$BUILD/liboqs" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DOQS_ENABLE_KEM=OFF -DOQS_ENABLE_SIG=ON \
  -DOQS_ENABLE_SIG_FALCON=ON -DOQS_ENABLE_SIG_STFL_XMSS=ON -DOQS_ENABLE_SIG_STFL_LMS=ON \
  -DOQS_MINIMAL_BUILD="SIG_falcon_512;SIG_falcon_1024;SIG_STFL_xmss_sha256_h10;SIG_STFL_xmssmt_sha256_h20_2;SIG_STFL_lms_sha256_h10_w4;SIG_STFL_lms_sha256_h10_w4_h10_w4" \
  -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON
cmake --build "$BUILD/liboqs" --parallel "$(nproc)"
cmake --install "$BUILD/liboqs"
fi

cat > "$TP/env.sh" <<EOF
export PQ_CAL_PREFIX="$PREFIX"
export OQS_INSTALL_PATH="$PREFIX"
export OPENSSL_MODULES="$PREFIX/lib64/ossl-modules"
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:\${LD_LIBRARY_PATH:-}"
export PATH="$PREFIX/bin:\$PATH"
EOF
printf '%s\n' "openssl_version=$OPENSSL_VERSION" "openssl_sha256=$OPENSSL_SHA256" \
  "liboqs_version=$LIBOQS_VERSION" "liboqs_commit=$LIBOQS_COMMIT" "liboqs_sha256=$LIBOQS_SHA256" \
  "oqs_use_openssl=ON" "stateful_key_sign_generation=ON" > "$TP/build_provenance.txt"
echo "Dependencies installed in $PREFIX"
