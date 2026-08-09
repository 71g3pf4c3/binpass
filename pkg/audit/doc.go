// Package audit checks a password store for weak, leaked, reused and expired
// passwords.
//
// Audit decrypts every entry in the store, which may require touching a hardware
// token for each one (ARCHITECTURE.md §3.3). The --parallel flag enables
// concurrent decryption, but it is not the default when a hardware token is
// detected, because hammering a token with concurrent touch requests is a bad
// user experience.
//
// Output is available in JSON (--format=json) for programmatic consumption and
// in a human-readable format grouped by severity. Passwords are never included
// in the output, only entry names and verdicts.
//
// Checks:
//   - HIBP: Uses k-anonymity protocol (5-char SHA-1 prefix). The full hash
//     never leaves the machine. Responses are cached in memory.
//   - Strength: zxcvbn-go score. Passwords scoring below 2 are flagged as weak.
//   - Reuse: SHA-1 hash comparison across entries. Reused passwords are grouped.
//   - Expired: Checks "expire:", "expires:", "expiry:" fields for past dates.
//
// Usage:
//
//	auditor := &audit.Auditor{
//	    Store:      myStore,
//	    Opts:       audit.DefaultOptions(),
//	    HIBPClient: audit.NewHIBPClient(),
//	}
//	report, _ := auditor.Run(ctx)
//	fmt.Println(audit.FormatHuman(report))
package audit
