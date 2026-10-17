#!/usr/bin/env sh
# Install the pinned sops release into PREFIX (default /usr/local/bin).
#
# Debian and Ubuntu do not package sops, so the Debian-based test paths —
# Dockerfile.test, the GitHub and GitLab unit-test jobs — fetch the upstream
# release binary. The version and checksum live here, once, so the three
# stay on the same build; the Nix dev shell gets sops from nixpkgs instead.
#
# Usage: scripts/install-sops.sh [PREFIX]
set -eu

VERSION=3.13.3
PREFIX="${1:-/usr/local/bin}"

case "$(uname -m)" in
	x86_64) ARCH=amd64; SHA=e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b ;;
	aarch64 | arm64) ARCH=arm64; SHA=53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77 ;;
	*) echo "install-sops: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

asset="sops-v${VERSION}.linux.${ARCH}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/sops" "https://github.com/getsops/sops/releases/download/v${VERSION}/${asset}"
echo "${SHA}  $tmp/sops" | sha256sum -c - >/dev/null
install -m 0755 "$tmp/sops" "${PREFIX}/sops"
"${PREFIX}/sops" --version
