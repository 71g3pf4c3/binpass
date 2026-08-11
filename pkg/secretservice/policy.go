package secretservice

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Action is what a policy rule decides.
type Action string

// The decisions a rule can make.
const (
	// ActionAllow hands over the secret.
	ActionAllow Action = "allow"
	// ActionDeny refuses it.
	ActionDeny Action = "deny"
	// ActionPrompt asks the user.
	ActionPrompt Action = "prompt"
)

// Rule is one entry in the access policy.
type Rule struct {
	// App matches the caller's executable path. "*" matches anything.
	App string `yaml:"app,omitempty"`
	// Collection restricts the rule to one collection.
	Collection string `yaml:"collection,omitempty"`
	// Attrs restricts the rule to items carrying these attributes.
	Attrs map[string]string `yaml:"attrs,omitempty"`
	// Action is what to do when the rule matches.
	Action Action `yaml:"action"`
}

// Config is the access policy.
type Config struct {
	// Default applies when no rule matches.
	Default Action `yaml:"default"`
	// Remember is how long a prompt decision is honoured.
	Remember time.Duration `yaml:"remember"`
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `yaml:"rules"`
	// Notify controls access notifications: off, on-access, on-prompt.
	Notify string `yaml:"notify"`
	// Audit records every access to the log.
	Audit bool `yaml:"audit"`
}

// DefaultConfig returns the policy used when none is configured.
//
// The default is allow, matching what gnome-keyring and pass-secret-service
// do. Denying by default would break every program on the machine the moment
// the provider starts, and a security control that has to be turned off to
// get work done is one that gets turned off.
func DefaultConfig() Config {
	return Config{
		Default:  ActionAllow,
		Remember: 8 * time.Hour,
		Notify:   "off",
	}
}

// AccessRecord is one line of the audit log.
type AccessRecord struct {
	// When the access happened.
	When time.Time
	// Caller is the executable that asked, when it could be identified.
	Caller string
	// Sender is the caller's unique bus name.
	Sender string
	// Collection holds the item.
	Collection string
	// Item is the item's identifier.
	Item string
	// Label is the item's label, which is easier to recognise than its ID.
	Label string
	// Allowed is what was decided.
	Allowed bool
}

// PolicyEngine decides access and keeps the audit log.
type PolicyEngine struct {
	// cfg is the configured policy.
	cfg Config
	// identify maps a bus sender to an executable path.
	identify func(sender string) (string, error)
	// notify writes access notifications, if any.
	notify io.Writer

	// mu guards the log and the remembered decisions.
	mu sync.Mutex
	// log holds recent accesses.
	log []AccessRecord
	// decisions remembers prompt answers until they expire.
	decisions map[string]decision
}

// decision is a remembered prompt answer.
type decision struct {
	// allowed is what the user chose.
	allowed bool
	// until is when the answer stops applying.
	until time.Time
}

// maxLog bounds the in-memory audit log. A long-running provider would
// otherwise grow without limit for a feature nobody reads that far back in.
const maxLog = 1000

// NewPolicyEngine returns an engine for a configuration.
//
// identify may be nil, in which case rules matching on the caller's
// executable never match and the default applies.
func NewPolicyEngine(cfg Config, identify func(sender string) (string, error), notify io.Writer) *PolicyEngine {
	if cfg.Default == "" {
		cfg.Default = ActionAllow
	}
	return &PolicyEngine{
		cfg:       cfg,
		identify:  identify,
		notify:    notify,
		decisions: map[string]decision{},
	}
}

// Allow implements Policy.
func (p *PolicyEngine) Allow(sender, collection string, it *Item) (bool, string) {
	caller := p.caller(sender)

	action := p.cfg.Default
	for _, r := range p.cfg.Rules {
		if r.matches(caller, collection, it) {
			action = r.Action
			break
		}
	}

	switch action {
	case ActionAllow:
		return true, ""
	case ActionDeny:
		return false, fmt.Sprintf("binpass policy denies %s access to this secret", describe(caller))
	case ActionPrompt:
		// A prompt needs a user in front of a terminal, and the provider
		// runs as a background service. Until the prompt UI exists this
		// falls back to the remembered answer, and refuses when there is
		// none: treating "ask the user" as "yes" would silently turn the
		// strictest setting into the weakest.
		if d, ok := p.remembered(caller, collection, it); ok {
			return d, ""
		}
		return false, fmt.Sprintf(
			"binpass policy requires confirmation for %s, and interactive prompts are not implemented yet; "+
				"set an explicit allow rule for it in secret-service.yaml", describe(caller))
	default:
		return false, fmt.Sprintf("unknown policy action %q", action)
	}
}

// Record implements Policy.
func (p *PolicyEngine) Record(sender, collection string, it *Item, allowed bool) {
	rec := AccessRecord{
		When:       time.Now(),
		Caller:     p.caller(sender),
		Sender:     sender,
		Collection: collection,
		Allowed:    allowed,
	}
	if it != nil {
		rec.Item = it.ID
		rec.Label = it.Label
	}

	p.mu.Lock()
	if p.cfg.Audit {
		p.log = append(p.log, rec)
		if len(p.log) > maxLog {
			p.log = p.log[len(p.log)-maxLog:]
		}
	}
	p.mu.Unlock()

	if p.notify != nil && p.cfg.Notify == "on-access" {
		verb := "read"
		if !allowed {
			verb = "was refused"
		}
		fmt.Fprintf(p.notify, "%s %s %s/%s\n", describe(rec.Caller), verb, collection, rec.Label)
	}
}

// Log returns the recorded accesses, newest last.
func (p *PolicyEngine) Log() []AccessRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]AccessRecord(nil), p.log...)
}

// LastAccessor returns the most recent access to an item.
func (p *PolicyEngine) LastAccessor(id string) (AccessRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.log) - 1; i >= 0; i-- {
		if p.log[i].Item == id {
			return p.log[i], true
		}
	}
	return AccessRecord{}, false
}

// Remember records a prompt answer for the configured duration.
func (p *PolicyEngine) Remember(caller, collection, itemID string, allowed bool) {
	if p.cfg.Remember <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.decisions[decisionKey(caller, collection, itemID)] = decision{
		allowed: allowed,
		until:   time.Now().Add(p.cfg.Remember),
	}
}

// remembered returns a stored answer that has not expired.
func (p *PolicyEngine) remembered(caller, collection string, it *Item) (bool, bool) {
	id := ""
	if it != nil {
		id = it.ID
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.decisions[decisionKey(caller, collection, id)]
	if !ok || time.Now().After(d.until) {
		return false, false
	}
	return d.allowed, true
}

// caller resolves a bus sender to an executable path.
func (p *PolicyEngine) caller(sender string) string {
	if p.identify == nil || sender == "" {
		return ""
	}
	exe, err := p.identify(sender)
	if err != nil {
		return ""
	}
	return exe
}

// matches reports whether a rule applies.
func (r Rule) matches(caller, collection string, it *Item) bool {
	if r.App != "" && r.App != "*" && r.App != caller {
		return false
	}
	if r.Collection != "" && r.Collection != collection {
		return false
	}
	if len(r.Attrs) > 0 {
		if it == nil {
			return false
		}
		for k, v := range r.Attrs {
			// "*" matches any value, which is how a rule says "anything
			// carrying this attribute at all".
			if v == "*" {
				if _, ok := it.Attributes[k]; !ok {
					return false
				}
				continue
			}
			if it.Attributes[k] != v {
				return false
			}
		}
	}
	return true
}

// describe names a caller for a message.
func describe(caller string) string {
	if caller == "" {
		return "an unidentified program"
	}
	return caller
}

// decisionKey builds the key a remembered answer is stored under.
func decisionKey(caller, collection, itemID string) string {
	return strings.Join([]string{caller, collection, itemID}, "\x00")
}
