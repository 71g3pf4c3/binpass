package crypto

// controllingTTY returns no terminal: GPG_TTY is a POSIX pinentry concern and
// has no meaning on Windows.
func controllingTTY() string { return "" }
