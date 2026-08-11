package secretservice_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/secretservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// identifyAs returns a caller resolver that always reports one executable,
// standing in for the /proc lookup the real provider does.
func identifyAs(exe string) func(string) (string, error) {
	return func(string) (string, error) { return exe, nil }
}

func TestPolicyDefaultAllows(t *testing.T) {
	p := secretservice.NewPolicyEngine(secretservice.DefaultConfig(), identifyAs("/usr/bin/git"), nil)

	// Allowing by default is what gnome-keyring and pass-secret-service do.
	// A provider that denied out of the box would break every program on the
	// machine the moment it started.
	allowed, _ := p.Allow(":1.42", "login", &secretservice.Item{ID: "x"})
	assert.True(t, allowed)
}

func TestPolicyDefaultDenyRefuses(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionDeny
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/curl"), nil)

	allowed, reason := p.Allow(":1.42", "login", &secretservice.Item{ID: "x"})
	assert.False(t, allowed)
	assert.Contains(t, reason, "/usr/bin/curl", "the refusal must name who was refused")
}

func TestPolicyRulesAreTriedInOrder(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionDeny
	cfg.Rules = []secretservice.Rule{
		{App: "/usr/bin/git", Attrs: map[string]string{"server": "github.com"}, Action: secretservice.ActionAllow},
		{App: "/usr/bin/git", Action: secretservice.ActionDeny},
	}
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/git"), nil)

	github := &secretservice.Item{ID: "a", Attributes: map[string]string{"server": "github.com"}}
	allowed, _ := p.Allow(":1.1", "login", github)
	assert.True(t, allowed, "the first matching rule wins")

	elsewhere := &secretservice.Item{ID: "b", Attributes: map[string]string{"server": "example.com"}}
	allowed, _ = p.Allow(":1.1", "login", elsewhere)
	assert.False(t, allowed, "the same program is refused for a different host")
}

func TestPolicyMatchesOnCollectionAndWildcards(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionAllow
	cfg.Rules = []secretservice.Rule{
		// Any program at all, for anything carrying an ssh attribute.
		{App: "*", Attrs: map[string]string{"application": "ssh"}, Action: secretservice.ActionDeny},
		{Collection: "work", Action: secretservice.ActionDeny},
	}
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/anything"), nil)

	ssh := &secretservice.Item{ID: "a", Attributes: map[string]string{"application": "ssh"}}
	allowed, _ := p.Allow(":1.1", "login", ssh)
	assert.False(t, allowed, `app: "*" must match every caller`)

	other := &secretservice.Item{ID: "b", Attributes: map[string]string{"application": "web"}}
	allowed, _ = p.Allow(":1.1", "login", other)
	assert.True(t, allowed)

	allowed, _ = p.Allow(":1.1", "work", other)
	assert.False(t, allowed, "a rule naming a collection applies to it")
}

func TestPolicyAttributeWildcardMatchesAnyValue(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionAllow
	cfg.Rules = []secretservice.Rule{
		{App: "*", Attrs: map[string]string{"application": "*"}, Action: secretservice.ActionDeny},
	}
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/x"), nil)

	withAttr := &secretservice.Item{ID: "a", Attributes: map[string]string{"application": "anything"}}
	allowed, _ := p.Allow(":1.1", "login", withAttr)
	assert.False(t, allowed, `"*" as a value means "carries this attribute at all"`)

	without := &secretservice.Item{ID: "b", Attributes: map[string]string{"server": "x"}}
	allowed, _ = p.Allow(":1.1", "login", without)
	assert.True(t, allowed, "an item without the attribute is not matched")
}

// TestPromptDeniesUntilItIsImplemented pins deliberate behaviour: there is no
// UI to prompt through yet, and treating "ask the user" as "yes" would turn
// the strictest setting into the weakest.
func TestPromptDeniesUntilItIsImplemented(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionPrompt
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/firefox"), nil)

	allowed, reason := p.Allow(":1.1", "login", &secretservice.Item{ID: "x"})
	assert.False(t, allowed)
	assert.Contains(t, reason, "not implemented",
		"the refusal must say why, or it looks like a bug")
}

func TestRememberedDecisionSatisfiesAPrompt(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionPrompt
	cfg.Remember = time.Hour
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/firefox"), nil)

	it := &secretservice.Item{ID: "item1"}
	p.Remember("/usr/bin/firefox", "login", "item1", true)

	allowed, _ := p.Allow(":1.1", "login", it)
	assert.True(t, allowed, "an answer the user already gave is honoured")

	// A different item is a different question.
	allowed, _ = p.Allow(":1.1", "login", &secretservice.Item{ID: "item2"})
	assert.False(t, allowed)
}

func TestRememberedDecisionExpires(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionPrompt
	cfg.Remember = time.Nanosecond
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/x"), nil)

	p.Remember("/x", "login", "item1", true)
	time.Sleep(time.Millisecond)

	allowed, _ := p.Allow(":1.1", "login", &secretservice.Item{ID: "item1"})
	assert.False(t, allowed, "a remembered answer must not outlive its window")
}

func TestAuditLogRecordsWhoReadWhat(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Audit = true
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/git"), nil)

	it := &secretservice.Item{ID: "item1", Label: "GitHub"}
	p.Record(":1.7", "login", it, true)
	p.Record(":1.7", "login", it, false)

	log := p.Log()
	require.Len(t, log, 2)
	assert.Equal(t, "/usr/bin/git", log[0].Caller)
	assert.Equal(t, ":1.7", log[0].Sender)
	assert.Equal(t, "GitHub", log[0].Label)
	assert.True(t, log[0].Allowed)
	assert.False(t, log[1].Allowed, "refusals are recorded too, or the log hides the interesting half")

	last, ok := p.LastAccessor("item1")
	require.True(t, ok)
	assert.False(t, last.Allowed, "the most recent access is the last one")

	_, ok = p.LastAccessor("nope")
	assert.False(t, ok)
}

func TestAuditOffKeepsNoLog(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Audit = false
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/x"), nil)

	p.Record(":1.1", "login", &secretservice.Item{ID: "a"}, true)
	assert.Empty(t, p.Log())
}

func TestNotifyOnAccessWritesALine(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Notify = "on-access"
	var buf bytes.Buffer
	p := secretservice.NewPolicyEngine(cfg, identifyAs("/usr/bin/git"), &buf)

	p.Record(":1.1", "login", &secretservice.Item{ID: "a", Label: "GitHub"}, true)
	assert.Contains(t, buf.String(), "/usr/bin/git")
	assert.Contains(t, buf.String(), "read")
	assert.Contains(t, buf.String(), "GitHub")

	buf.Reset()
	p.Record(":1.1", "login", &secretservice.Item{ID: "a", Label: "GitHub"}, false)
	assert.Contains(t, buf.String(), "was refused")
}

// TestUnidentifiableCallerStillGetsADecision covers the case the policy has
// to survive: /proc is gone, the process exited, or the bus will not say.
// Rules naming an executable cannot match, so the default applies.
func TestUnidentifiableCallerStillGetsADecision(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionDeny
	cfg.Rules = []secretservice.Rule{
		{App: "/usr/bin/git", Action: secretservice.ActionAllow},
	}
	failing := func(string) (string, error) { return "", errors.New("no such process") }
	p := secretservice.NewPolicyEngine(cfg, failing, nil)

	allowed, reason := p.Allow(":1.1", "login", &secretservice.Item{ID: "x"})
	assert.False(t, allowed, "an unidentified caller must not inherit another program's grant")
	assert.Contains(t, reason, "unidentified")
}

func TestNilIdentifierFallsBackToTheDefault(t *testing.T) {
	cfg := secretservice.DefaultConfig()
	cfg.Default = secretservice.ActionAllow
	p := secretservice.NewPolicyEngine(cfg, nil, nil)

	allowed, _ := p.Allow(":1.1", "login", &secretservice.Item{ID: "x"})
	assert.True(t, allowed)
}
