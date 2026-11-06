#!/bin/bash
# Tải qemu-aarch64 chế độ user vào thư mục riêng, không cần sudo.
# Binary thật nằm trong gói qemu-user; qemu-user-static chỉ gồm symlink.
set -euo pipefail
DIR="$HOME/sdc-router/qemu"
POOL="https://archive.ubuntu.com/ubuntu/pool/universe/q/qemu/"
mkdir -p "$DIR"
cd "$DIR"
NAME="$(curl -fsSL "$POOL" | grep -oE 'qemu-user_[^"]*_amd64\.deb' | sort -uV | tail -1)"
echo "Tải $NAME"
curl -fsSL -o qemu.deb "$POOL$NAME"
rm -rf x
dpkg -x qemu.deb x
ln -sf "$DIR/x/usr/bin/qemu-aarch64" "$DIR/qemu-aarch64"
"$DIR/qemu-aarch64" --version | head -1
"$DIR/qemu-aarch64" "$(dirname "${BASH_SOURCE[0]}")/../build/hello_aarch64" | head -4
