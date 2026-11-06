#!/bin/bash
# Tải toolchain musl (Bootlin), kiểm sha256 và build hello link tĩnh cho router.
# Cách dùng trong WSL:  bash setup_toolchain.sh aarch64|armv7
set -euo pipefail

ARCH="${1:-}"
RELEASE="stable-2024.05-1"
case "$ARCH" in
  aarch64) BOOTLIN="aarch64";      TRIPLE="aarch64-buildroot-linux-musl" ;;
  armv7)   BOOTLIN="armv7-eabihf"; TRIPLE="arm-buildroot-linux-musleabihf" ;;
  *) echo "Cách dùng: bash setup_toolchain.sh aarch64|armv7" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="$(dirname "$HERE")"
# Giữ toolchain trên ổ Linux của WSL: nhanh hơn /mnt/d và giữ được symlink.
TC_ROOT="$HOME/sdc-router/toolchains"
NAME="${BOOTLIN}--musl--${RELEASE}"
BASE_URL="https://toolchains.bootlin.com/downloads/releases/toolchains/${BOOTLIN}/tarballs"
TC_DIR="$TC_ROOT/$NAME"
OUT_DIR="$PROJECT/build"

mkdir -p "$TC_ROOT" "$OUT_DIR"

if [ ! -x "$TC_DIR/bin/${TRIPLE}-g++" ]; then
  cd "$TC_ROOT"
  echo "[1/3] Tải $NAME"
  curl -fL --retry 3 -o "$NAME.tar.xz" "$BASE_URL/$NAME.tar.xz"
  curl -fsSL --retry 3 -o "$NAME.sha256" "$BASE_URL/$NAME.sha256"
  echo "[2/3] Kiểm sha256 và giải nén"
  sha256sum -c "$NAME.sha256"
  tar -xJf "$NAME.tar.xz"
  (cd "$TC_DIR" && ./relocate-sdk.sh >/dev/null)
  rm -f "$NAME.tar.xz"
else
  echo "[1-2/3] Đã có toolchain tại $TC_DIR"
fi

echo "[3/3] Build hello_$ARCH"
OUT="$OUT_DIR/hello_$ARCH"
"$TC_DIR/bin/${TRIPLE}-g++" -std=c++17 -Os -static -pthread -s \
  "$HERE/hello.cpp" -o "$OUT"

"$TC_DIR/bin/${TRIPLE}-g++" --version | head -1
file "$OUT"
ls -la "$OUT"
