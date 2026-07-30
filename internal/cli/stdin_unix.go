package cli

import "os"

// syscallStdin returns the file descriptor of standard input.
func syscallStdin() uintptr { return os.Stdin.Fd() }
