#!/usr/bin/env bash
# Run the unit tests through internal/testreport.
#
# Why not plain `go test ./...`: quiet test output hides skips entirely, and
# the golden suite used to exit TestMain with 0 without running a single
# test, so a green run on a machine without pass/gpg/rclone/restic proved
# nothing about pass(1) compatibility while looking complete. `go test -json`
# carries every skip event; the reporter renders the same quiet output as
# before and appends a warning naming the missing tools.
#
# The exit code stays whatever `go test` returned — skips are visibility,
# not gating.
set -o pipefail

GO=${GO:-go}

"$GO" test -json ./... | "$GO" run ./internal/testreport
