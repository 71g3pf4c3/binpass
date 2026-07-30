// Package version exposes build metadata injected via -ldflags.
package version

// Build metadata, overridden at link time with -X.
var (
	// Version is the release version or git describe output.
	Version = "dev"
	// Commit is the short git commit hash.
	Commit = "none"
	// BuildDate is the UTC build timestamp.
	BuildDate = "unknown"
)
