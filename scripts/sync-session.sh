#!/usr/bin/env bash
# Run the sync and snapshot integration suites against the real tools.
#
# The rclone transports, the git remote and the restic snapshots skip
# silently when their binaries are absent, and the S3 tests skip when no
# Docker daemon answers — the same silent-skip trade the golden suite
# makes for pass. This script runs inside Dockerfile.sync, where the
# binaries come from Debian and the runner mounts the Docker socket, so
# the skips have no excuse left: a missing tool is a broken image, not a
# skipped test, and is reported as a failure.
set -uo pipefail

missing=0
for tool in rclone restic git; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "sync-session: $tool is not on PATH: its tests would skip silently" >&2
		missing=1
	fi
done
if [[ ! -S /var/run/docker.sock ]]; then
	echo "sync-session: /var/run/docker.sock is not mounted: the MinIO-backed S3 tests would skip silently" >&2
	echo "sync-session: run with: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock <image>" >&2
	missing=1
fi
[[ $missing -eq 0 ]] || exit 1

# The packages whose tests talk to the outside world: the transports and
# snapshots themselves, and the CLI flows that drive them (two-device sync,
# conflict handling, history and restore). Everything runs in temporary
# directories the tests create; nothing here touches a developer's store.
go test -count=1 ./pkg/remote/ ./pkg/sync/ ./internal/cli/
