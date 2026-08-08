package cli

import (
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
)

// --- csvEscape ---

func TestCSVEscape(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"simple", "simple"},
		{"with,comma", `"with,comma"`},
		{"with\"quote", `"with""quote"`},
		{"with\nnewline", "\"with\nnewline\""},
		{"with\r\ncrlf", "\"with\r\ncrlf\""},
		{"кириллица", "кириллица"},
		{"emoji 🎉", "emoji 🎉"},
	}
	for _, tc := range tests {
		got := csvEscape(tc.in)
		if got != tc.want {
			t.Errorf("csvEscape(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCSVEscapeMultibyte(t *testing.T) {
	// Russian text with comma — must be quoted, not double-encoded.
	got := csvEscape("Привет,мир")
	if !strings.HasPrefix(got, `"`) {
		t.Errorf("expected quoted result for multi-byte string with comma, got %q", got)
	}
}

// --- command construction ---

func TestNewImportCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newImportCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	if !cmd.HasFlags() {
		t.Error("import should have flags")
	}
	for _, name := range []string{"format", "dry-run", "force", "encoding"} {
		if f := cmd.Flags().Lookup(name); f == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
}

func TestNewExportCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newExportCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	if f := cmd.Flags().Lookup("format"); f == nil {
		t.Error("missing --format flag")
	}
}

func TestNewAuditCmd(t *testing.T) {
	cfg := config.Default()
	app := NewApp(cfg)
	cmd := newAuditCmd(app)

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
	for _, name := range []string{"format", "parallel", "no-hibp"} {
		if f := cmd.Flags().Lookup(name); f == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
}
