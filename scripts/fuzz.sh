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

# Modules to search, longest path first so that a file under server/ is
# attributed to the server module rather than to the root one.
modules=(server .)

# module_of prints the module a file belongs to.
module_of() {
	local file="$1" m
	# find prints paths as "./server/pkg/...", so compare without the prefix.
	local rel="${file#./}"
	for m in "${modules[@]}"; do
		[[ "$m" == "." ]] && continue
		[[ "$rel" == "$m/"* ]] && { printf '%s' "$m"; return; }
	done
	printf '.'
}

failed=()
count=0

while IFS= read -r file; do
	module="$(module_of "$file")"
	dir="$(dirname "$file")"
	# The package path has to be relative to its own module.
	if [[ "$module" == "." ]]; then
		pkg="./${dir#./}"
	else
		pkg="./${dir#./"$module"/}"
	fi

	while IFS= read -r target; do
		count=$((count + 1))
		printf '\n== %s %s\n' "$file" "$target"
		if ! (cd "$module" && go test "$pkg" \
			-run "^${target}\$" -fuzz "^${target}\$" -fuzztime="$fuzztime"); then
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
