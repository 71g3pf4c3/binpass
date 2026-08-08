package importer

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/store"
)

// PlanEntry is the result of planning an import: it shows what will be written
// without actually writing anything. Used by --dry-run.
type PlanEntry struct {
	// StorePath is the path where the entry will be stored.
	StorePath string

	// Title is the original entry title from the source.
	Title string

	// HasPassword reports whether the entry has a non-empty password.
	HasPassword bool

	// HasTOTP reports whether the entry carries a TOTP secret.
	HasTOTP bool

	// AttachmentCount is the number of attachments.
	AttachmentCount int

	// Conflict reports that an entry with the same path already exists in the
	// store.
	Conflict bool
}

// Plan computes what an import would write without writing anything.
func Plan(s *store.Store, entries []*Entry) []PlanEntry {
	existing := make(map[string]bool)
	if names, err := s.List(""); err == nil {
		for _, n := range names {
			existing[n] = true
		}
	}

	var plans []PlanEntry
	seenPaths := make(map[string]int)
	for _, e := range entries {
		p, err := e.StorePath()
		if err != nil {
			p = NormalizePath(e.Group, e.Title)
		}

		// Deduplicate within the import set.
		n := seenPaths[p]
		seenPaths[p] = n + 1
		if n > 0 {
			p = fmt.Sprintf("%s-%d", p, n+1)
		}

		plans = append(plans, PlanEntry{
			StorePath:       p,
			Title:           e.Title,
			HasPassword:     e.Password != "",
			HasTOTP:         e.TOTPURI != "",
			AttachmentCount: len(e.Attachments),
			Conflict:        existing[p],
		})
	}
	return plans
}

// WriteEntries writes all entries to the store. It skips entries with invalid
// paths (reporting them via the returned errors) and overwrites existing entries
// only when force is true.
func WriteEntries(s *store.Store, entries []*Entry, force bool) ([]string, []error) {
	var written []string
	var errs []error

	seenPaths := make(map[string]int)
	for _, e := range entries {
		p, err := e.StorePath()
		if err != nil {
			errs = append(errs, fmt.Errorf("skip %q: %w", e.Title, err))
			continue
		}

		// Deduplicate within the import set.
		n := seenPaths[p]
		seenPaths[p] = n + 1
		if n > 0 {
			p = fmt.Sprintf("%s-%d", p, n+1)
		}

		// Check for conflicts.
		if s.Exists(p) && !force {
			errs = append(errs, fmt.Errorf("skip %q: entry %q already exists (use --force to overwrite)", e.Title, p))
			continue
		}

		sec := e.ToSecret()
		if err := s.Set(p, sec); err != nil {
			errs = append(errs, fmt.Errorf("write %q: %w", p, err))
			continue
		}
		written = append(written, p)

		// Write attachments as separate entries with base64-encoded content.
		for i, att := range e.Attachments {
			attPath, err := e.AttachmentStorePath(i)
			if err != nil {
				errs = append(errs, fmt.Errorf("attachment %d of %q: %w", i, e.Title, err))
				continue
			}
			b64Content := base64.StdEncoding.EncodeToString(att.Data)
			attSec := secret.New(b64Content, "")
			if err := s.Set(attPath, attSec); err != nil {
				errs = append(errs, fmt.Errorf("write attachment %q: %w", attPath, err))
			}
			written = append(written, attPath)
		}
	}
	return written, errs
}

// FormatPlan formats a dry-run plan for display.
func FormatPlan(plans []PlanEntry) string {
	var sb strings.Builder
	sb.WriteString("Import plan:\n")
	for i, p := range plans {
		sb.WriteString(fmt.Sprintf("  %d. %s", i+1, p.StorePath))
		if p.Conflict {
			sb.WriteString(" [OVERWRITE]")
		}
		if p.HasPassword {
			sb.WriteString(" (password)")
		}
		if p.HasTOTP {
			sb.WriteString(" (totp)")
		}
		if p.AttachmentCount > 0 {
			sb.WriteString(fmt.Sprintf(" (%d attachments)", p.AttachmentCount))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d entries\n", len(plans)))
	return sb.String()
}
