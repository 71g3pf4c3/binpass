package tui

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secret"
	tea "github.com/charmbracelet/bubbletea"
)

// hotpResult carries the outcome of an HOTP reveal: the code that was
// produced and the secret with the advanced counter, so the detail view
// can re-arm itself from the entry that is now on disk.
type hotpResult struct {
	code string
	sec  *secret.Secret
	err  error
}

// hotpRevealCmd computes one HOTP code, writes the advanced counter back
// to the store, and copies the code — the same sequence the otp command
// and the menu run, so all three agree on which code is current. The
// counter must be persisted before the code is used: a code from a
// counter that was never written is one the server will never accept
// again.
func (m Model) hotpRevealCmd() tea.Cmd {
	s := m.store
	name := m.current
	sec := m.sec
	cfg := m.otpCfg
	uri, _ := sec.OTP()
	cb := m.clipBackend
	dur := m.cfg.ClipTime
	return func() tea.Msg {
		code, err := cfg.Code(time.Now())
		if err != nil {
			return hotpResult{err: err}
		}
		updated, err := advanceCounter(sec, uri, cfg.Next().Counter)
		if err != nil {
			return hotpResult{err: err}
		}
		if err := s.Set(name, updated); err != nil {
			return hotpResult{err: err}
		}
		if cb != nil {
			ctx, cancel := context.WithTimeout(context.Background(), dur+time.Second)
			defer cancel()
			if err := clipCopy(ctx, cb, code, dur); err != nil {
				return hotpResult{code: code, sec: updated, err: err}
			}
		}
		return hotpResult{code: code, sec: updated}
	}
}

// advanceCounter returns a copy of sec with the otpauth URI's counter
// rewritten to n, leaving every other byte alone.
func advanceCounter(sec *secret.Secret, uri string, n uint64) (*secret.Secret, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("counter", strconv.FormatUint(n, 10))
	u.RawQuery = q.Encode()
	return sec.ReplaceLineContaining(uri, u.String()), nil
}
