#!/usr/bin/env bash
# Run every fuzz target in the repository for a short time each.
#
# Go fuzzes one target per `go test` invocation, so a fixed list in the CI
# workflow would silently stop covering new targets the moment someone adds
# one. This discovers them instead.
#
# Usage: scripts/fuzz.sh [seconds-per-target]
set -euo pipefail

fuzztime="${1:-${FUZZTIME:-20}}s"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

failed=()
count=0

while IFS= read -r file; do
	pkg="./$(dirname "${file#./}")"

	while IFS= read -r target; do
		count=$((count + 1))
		printf '\n== %s %s\n' "$file" "$target"
		if ! go test "$pkg" \
			-run "^${target}\$" -fuzz "^${target}\$" -fuzztime="$fuzztime"; then
			failed+=("$file $target")
		fi
	done < <(sed -nE 's/^func (Fuzz[A-Za-z0-9_]*)\(f \*testing\.F\).*/\1/p' "$file")
done < <(find . -name '*_test.go' -not -path './.git/*' -print0 \
	| xargs -0 grep -l -E '^func Fuzz[A-Za-z0-9_]*\(f \*testing\.F\)' \
	| sort)

printf '\n== Result\n  %d target(s), %d failed\n' "$count" "${#failed[@]}"
for f in "${failed[@]:-}"; do
	[[ -n "$f" ]] && printf '  FAILED: %s\n' "$f"
done
[[ ${#failed[@]} -eq 0 ]]
