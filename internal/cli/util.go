package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// stdinReader is a process-wide buffered reader over os.Stdin, shared so that
// successive prompted reads do not discard already-buffered input.
var stdinReader = bufio.NewReader(os.Stdin)

// readLineStdin reads a single trimmed line from stdin.
func readLineStdin(prompt string) (string, error) {
	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readAllStdin reads all of stdin.
func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// clipCopy copies text to the system clipboard, clearing it after ttl.
func clipCopy(text string, ttl time.Duration) error {
	cmd, args := clipCommand()
	if cmd == "" {
		return fmt.Errorf("clip: no clipboard tool found")
	}
	if err := runClip(cmd, args, text); err != nil {
		return err
	}
	go func() {
		time.Sleep(ttl)
		_ = runClip(cmd, args, "")
	}()
	return nil
}

// clipCommand selects a clipboard command for the current platform.
func clipCommand() (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "pbcopy", nil
	case "windows":
		return "clip", nil
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			return "wl-copy", nil
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			return "xclip", []string{"-selection", "clipboard"}
		}
		if _, err := exec.LookPath("xsel"); err == nil {
			return "xsel", []string{"--clipboard", "--input"}
		}
		return "", nil
	}
}

// runClip pipes text into the clipboard command.
func runClip(name string, args []string, text string) error {
	c := exec.Command(name, args...)
	c.Stdin = strings.NewReader(text)
	return c.Run()
}
