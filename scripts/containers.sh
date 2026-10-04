#!/usr/bin/env bash
# Build and run every container test suite in one go.
#
# This is the pre-merge one-liner: `make containers`. It discovers the
# suites from Dockerfile.* so a new one is picked up automatically; the
# flags a suite needs beyond a plain run are named in run_flags below,
# because a suite that silently needs --privileged is a suite nobody can
# run by hand.
set -uo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
	echo "containers: docker is not on PATH" >&2
	exit 1
fi

# run_flags prints the extra `docker run` flags a suite needs.
run_flags() {
	case "$1" in
	# dm-crypt needs the device mapper of the host kernel.
	luks) echo "--privileged" ;;
	# The S3 tests start a real MinIO through testcontainers, which talks
	# to the Docker daemon this socket belongs to.
	sync) echo "-v /var/run/docker.sock:/var/run/docker.sock" ;;
	esac
}

suites=$(find . -maxdepth 1 -name 'Dockerfile.*' | sed 's|./Dockerfile\.||' | sort)
if [[ -z $suites ]]; then
	echo "containers: no Dockerfile.* found" >&2
	exit 1
fi

failed=()
for suite in $suites; do
	printf '\n\033[1m== suite: %s\033[0m\n' "$suite"
	if docker build -f "Dockerfile.$suite" -t "binpass-$suite" . \
		&& docker run --rm $(run_flags "$suite") "binpass-$suite"; then
		printf '\033[32mPASS\033[0m %s\n' "$suite"
	else
		printf '\033[31mFAIL\033[0m %s\n' "$suite"
		failed+=("$suite")
	fi
done

printf '\n'
if [[ ${#failed[@]} -gt 0 ]]; then
	printf 'failed suites: %s\n' "${failed[*]}"
	exit 1
fi
printf 'all container suites green\n'
