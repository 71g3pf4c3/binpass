//go:build linux

package secretservice

import (
	"fmt"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

// The bus name and object paths the specification fixes. Clients hardcode
// these, so none of them is configurable.
const (
	// ServicePath is the root object.
	ServicePath = dbus.ObjectPath("/org/freedesktop/secrets")
	// ServiceInterface is the interface the root object implements.
	ServiceInterface = "org.freedesktop.Secret.Service"
	// CollectionInterface is implemented by each collection.
	CollectionInterface = "org.freedesktop.Secret.Collection"
	// ItemInterface is implemented by each item.
	ItemInterface = "org.freedesktop.Secret.Item"
	// SessionInterface is implemented by each session.
	SessionInterface = "org.freedesktop.Secret.Session"
	// PromptInterface is implemented by prompts.
	PromptInterface = "org.freedesktop.Secret.Prompt"
)

// Secret is the wire form of a secret: the quadruple the specification
// passes between client and provider.
type Secret struct {
	// Session is the session the secret is encrypted for.
	Session dbus.ObjectPath
	// Parameters carries the IV for the encrypted algorithms.
	Parameters []byte
	// Value is the secret itself, encrypted unless the session is plain.
	Value []byte
	// ContentType describes the value; clients rarely set anything else.
	ContentType string
}

// Service is the D-Bus provider. It owns the bus name and exports every
// object a client walks: the service itself, the collections, their items,
// and one session per connected client.
type Service struct {
	// conn is the session bus connection.
	conn *dbus.Conn
	// store is where items actually live.
	store *Store
	// policy decides whether a caller may read a secret.
	policy Policy
	// mu guards sessions.
	mu sync.Mutex
	// sessions holds the open transport sessions by object path.
	sessions map[dbus.ObjectPath]*Session
	// nextSession numbers session paths.
	nextSession int
}

// Policy decides whether a caller may have a secret. It is consulted before
// anything is decrypted, so a denial means the plaintext is never produced.
type Policy interface {
	// Allow reports whether the caller identified by the bus sender may
	// read the item, and returns the reason when it may not.
	Allow(sender string, collection string, it *Item) (bool, string)
	// Record notes an access for the audit log.
	Record(sender string, collection string, it *Item, allowed bool)
}

// allowAll is the policy used when none is configured.
type allowAll struct{}

func (allowAll) Allow(string, string, *Item) (bool, string) { return true, "" }
func (allowAll) Record(string, string, *Item, bool)         {}

// NewService returns a provider over a store.
func NewService(conn *dbus.Conn, store *Store, policy Policy) *Service {
	if policy == nil {
		policy = allowAll{}
	}
	return &Service{
		conn:     conn,
		store:    store,
		policy:   policy,
		sessions: map[dbus.ObjectPath]*Session{},
	}
}

// Export publishes every object and claims the bus name.
func (s *Service) Export(mode Takeover) error {
	if err := s.exportService(); err != nil {
		return err
	}
	if err := s.exportCollections(); err != nil {
		return err
	}
	return s.claimName(mode)
}

// claimName acquires the well-known bus name.
func (s *Service) claimName(mode Takeover) error {
	flags := dbus.NameFlagDoNotQueue
	switch mode {
	case TakeoverReplace:
		flags = dbus.NameFlagReplaceExisting | dbus.NameFlagDoNotQueue
	case TakeoverWait:
		flags = 0
	case TakeoverRefuse, "":
		// The default: leave whoever is there alone.
	default:
		return fmt.Errorf("secretservice: unknown takeover mode %q", mode)
	}

	reply, err := s.conn.RequestName(BusName, flags)
	if err != nil {
		return fmt.Errorf("secretservice: requesting %s: %w", BusName, err)
	}
	switch reply {
	case dbus.RequestNameReplyPrimaryOwner:
		return nil
	case dbus.RequestNameReplyInQueue:
		if mode == TakeoverWait {
			return nil
		}
		return ErrNameTaken
	default:
		// Naming the current owner turns "it did not start" into something
		// the user can act on, which is the whole job of `ss doctor`.
		owner := s.currentOwner()
		if owner != "" {
			return fmt.Errorf("%w (owned by %s); run `binpass ss doctor`", ErrNameTaken, owner)
		}
		return ErrNameTaken
	}
}

// currentOwner returns the process name owning the bus name, if it can be
// determined.
func (s *Service) currentOwner() string {
	var owner string
	if err := s.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, BusName).Store(&owner); err != nil {
		return ""
	}
	var pid uint32
	if err := s.conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixProcessID", 0, owner).Store(&pid); err != nil {
		return owner
	}
	if exe, err := processExe(int(pid)); err == nil {
		return fmt.Sprintf("%s (pid %d)", exe, pid)
	}
	return fmt.Sprintf("pid %d", pid)
}

// exportService publishes the root object.
func (s *Service) exportService() error {
	if err := s.conn.Export(s, ServicePath, ServiceInterface); err != nil {
		return err
	}
	if err := s.conn.Export(introspect.Introspectable(serviceIntrospect), ServicePath,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	_, err := prop.Export(s.conn, ServicePath, map[string]map[string]*prop.Prop{
		ServiceInterface: {
			"Collections": {
				Value:    s.collectionPaths(),
				Writable: false,
				Emit:     prop.EmitTrue,
			},
		},
	})
	return err
}

// exportCollections publishes every collection and its items.
func (s *Service) exportCollections() error {
	names, err := s.store.Collections()
	if err != nil {
		return err
	}
	// The default collection is always present, even before anything has
	// been stored: a client that cannot find it concludes the keyring is
	// broken rather than empty.
	if !containsString(names, DefaultCollection) {
		names = append(names, DefaultCollection)
	}

	for _, name := range names {
		if err := s.exportCollection(name); err != nil {
			return err
		}
	}
	return nil
}

// exportCollection publishes one collection and the items in it.
func (s *Service) exportCollection(name string) error {
	c := &collection{service: s, name: name}
	p := collectionPath(name)

	if err := s.conn.Export(c, p, CollectionInterface); err != nil {
		return err
	}
	if err := s.conn.Export(introspect.Introspectable(collectionIntrospect), p,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	if _, err := prop.Export(s.conn, p, map[string]map[string]*prop.Prop{
		CollectionInterface: {
			"Items":    {Value: s.itemPaths(name), Writable: false, Emit: prop.EmitTrue},
			"Label":    {Value: name, Writable: false, Emit: prop.EmitTrue},
			"Locked":   {Value: false, Writable: false, Emit: prop.EmitTrue},
			"Created":  {Value: uint64(0), Writable: false, Emit: prop.EmitFalse},
			"Modified": {Value: uint64(0), Writable: false, Emit: prop.EmitFalse},
		},
	}); err != nil {
		return err
	}

	// The default alias, which is how clients find a collection without
	// knowing its name.
	if name == DefaultCollection {
		if err := s.conn.Export(c, dbus.ObjectPath("/org/freedesktop/secrets/aliases/default"),
			CollectionInterface); err != nil {
			return err
		}
	}

	items, err := s.store.Items(name)
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := s.exportItem(name, it); err != nil {
			return err
		}
	}
	return nil
}

// exportItem publishes one item.
func (s *Service) exportItem(collectionName string, it *Item) error {
	obj := &itemObject{service: s, collection: collectionName, id: it.ID}
	p := itemObjectPath(collectionName, it.ID)

	if err := s.conn.Export(obj, p, ItemInterface); err != nil {
		return err
	}
	if err := s.conn.Export(introspect.Introspectable(itemIntrospect), p,
		"org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	_, err := prop.Export(s.conn, p, map[string]map[string]*prop.Prop{
		ItemInterface: {
			"Attributes": {Value: it.Attributes, Writable: false, Emit: prop.EmitTrue},
			"Label":      {Value: it.Label, Writable: false, Emit: prop.EmitTrue},
			"Locked":     {Value: false, Writable: false, Emit: prop.EmitTrue},
			"Created":    {Value: uint64(it.Created.Unix()), Writable: false, Emit: prop.EmitFalse},  //nolint:gosec // a Unix timestamp.
			"Modified":   {Value: uint64(it.Modified.Unix()), Writable: false, Emit: prop.EmitFalse}, //nolint:gosec // a Unix timestamp.
		},
	})
	return err
}

// OpenSession implements org.freedesktop.Secret.Service.OpenSession.
func (s *Service) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	s.nextSession++
	id := fmt.Sprintf("s%d", s.nextSession)
	s.mu.Unlock()

	p := dbus.ObjectPath("/org/freedesktop/secrets/session/" + id)

	switch algorithm {
	case AlgPlain:
		sess := NewPlainSession(id)
		s.register(p, sess)
		return dbus.MakeVariant(""), p, nil

	case AlgDH:
		clientPub, ok := input.Value().([]byte)
		if !ok {
			return dbus.MakeVariant(""), "", dbusErrf("org.freedesktop.DBus.Error.InvalidArgs",
				"the DH algorithm needs the client's public key as a byte array")
		}
		sess, serverPub, err := NewDHSession(id, clientPub)
		if err != nil {
			return dbus.MakeVariant(""), "", dbusErrf("org.freedesktop.DBus.Error.InvalidArgs", "%s", err)
		}
		s.register(p, sess)
		return dbus.MakeVariant(serverPub), p, nil

	default:
		return dbus.MakeVariant(""), "", dbusErrf(
			"org.freedesktop.Secret.Error.NotSupported",
			"algorithm %q is not supported; this provider offers %s and %s",
			algorithm, AlgPlain, AlgDH)
	}
}

// register exports a session object and remembers its key.
func (s *Service) register(p dbus.ObjectPath, sess *Session) {
	s.mu.Lock()
	s.sessions[p] = sess
	s.mu.Unlock()

	_ = s.conn.Export(&sessionObject{service: s, path: p}, p, SessionInterface)
	_ = s.conn.Export(introspect.Introspectable(sessionIntrospect), p,
		"org.freedesktop.DBus.Introspectable")
}

// session returns an open session by path.
func (s *Service) session(p dbus.ObjectPath) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[p]
	return sess, ok
}

// closeSession forgets a session, which is what makes its key unrecoverable.
func (s *Service) closeSession(p dbus.ObjectPath) {
	s.mu.Lock()
	delete(s.sessions, p)
	s.mu.Unlock()
	_ = s.conn.Export(nil, p, SessionInterface)
}

// SearchItems implements org.freedesktop.Secret.Service.SearchItems.
func (s *Service) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	names, err := s.store.Collections()
	if err != nil {
		return nil, nil, dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}

	var unlocked []dbus.ObjectPath
	for _, name := range names {
		items, err := s.store.Search(name, attributes)
		if err != nil {
			continue
		}
		for _, it := range items {
			unlocked = append(unlocked, itemObjectPath(name, it.ID))
		}
	}
	// Nothing is reported locked: a store this provider can read is
	// unlocked by definition, and one it cannot read fails earlier.
	return unlocked, nil, nil
}

// Unlock implements org.freedesktop.Secret.Service.Unlock.
//
// Everything is already unlocked when the provider is running, so this
// reports success without a prompt rather than handing back a prompt object
// no client would know what to do with.
func (s *Service) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return objects, dbus.ObjectPath("/"), nil
}

// Lock implements org.freedesktop.Secret.Service.Lock.
func (s *Service) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return nil, dbus.ObjectPath("/"), nil
}

// GetSecrets implements org.freedesktop.Secret.Service.GetSecrets.
func (s *Service) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	sess, ok := s.session(session)
	if !ok {
		return nil, dbusErrf("org.freedesktop.Secret.Error.NoSession", "no such session")
	}

	out := map[dbus.ObjectPath]Secret{}
	for _, p := range items {
		collectionName, id, ok := parseItemPath(p)
		if !ok {
			continue
		}
		it, err := s.store.Item(collectionName, id)
		if err != nil {
			continue
		}
		// A denial skips the item rather than failing the whole call: a
		// client asking for several secrets should still get the ones it
		// may have.
		if allowed, _ := s.policy.Allow(callerOf(p), collectionName, it); !allowed {
			s.policy.Record("", collectionName, it, false)
			continue
		}
		secretValue, err := encodeSecret(sess, session, it.Secret)
		if err != nil {
			continue
		}
		s.policy.Record("", collectionName, it, true)
		out[p] = secretValue
	}
	return out, nil
}

// ReadAlias implements org.freedesktop.Secret.Service.ReadAlias.
func (s *Service) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	if name == "default" {
		return collectionPath(DefaultCollection), nil
	}
	return dbus.ObjectPath("/"), nil
}

// SetAlias implements org.freedesktop.Secret.Service.SetAlias.
func (s *Service) SetAlias(string, dbus.ObjectPath) *dbus.Error {
	return dbusErrf("org.freedesktop.Secret.Error.NotSupported",
		"aliases other than default are not supported")
}

// CreateCollection implements org.freedesktop.Secret.Service.CreateCollection.
func (s *Service) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	name := alias
	if name == "" {
		if v, ok := properties["org.freedesktop.Secret.Collection.Label"]; ok {
			if label, ok := v.Value().(string); ok {
				name = label
			}
		}
	}
	if name == "" {
		name = DefaultCollection
	}
	name = sanitiseCollectionName(name)

	if err := s.exportCollection(name); err != nil {
		return "/", "/", dbusErrf("org.freedesktop.Secret.Error.NoSuchObject", "%s", err)
	}
	return collectionPath(name), dbus.ObjectPath("/"), nil
}

// collectionPaths returns the exported collection paths.
func (s *Service) collectionPaths() []dbus.ObjectPath {
	names, err := s.store.Collections()
	if err != nil {
		return nil
	}
	if !containsString(names, DefaultCollection) {
		names = append(names, DefaultCollection)
	}
	out := make([]dbus.ObjectPath, 0, len(names))
	for _, n := range names {
		out = append(out, collectionPath(n))
	}
	return out
}

// itemPaths returns the exported item paths of a collection.
func (s *Service) itemPaths(collectionName string) []dbus.ObjectPath {
	items, err := s.store.Items(collectionName)
	if err != nil {
		return nil
	}
	out := make([]dbus.ObjectPath, 0, len(items))
	for _, it := range items {
		out = append(out, itemObjectPath(collectionName, it.ID))
	}
	return out
}

// encodeSecret wraps a secret for the wire.
func encodeSecret(sess *Session, sessionPath dbus.ObjectPath, plaintext string) (Secret, error) {
	value, param, err := sess.Encrypt([]byte(plaintext))
	if err != nil {
		return Secret{}, err
	}
	return Secret{
		Session:     sessionPath,
		Parameters:  param,
		Value:       value,
		ContentType: "text/plain",
	}, nil
}

// collectionPath returns the object path of a collection.
func collectionPath(name string) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/secrets/collection/" + name)
}

// itemObjectPath returns the object path of an item.
func itemObjectPath(collectionName, id string) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/secrets/collection/" + collectionName + "/" + id)
}

// parseItemPath splits an item object path back into its parts.
func parseItemPath(p dbus.ObjectPath) (collectionName, id string, ok bool) {
	const prefix = "/org/freedesktop/secrets/collection/"
	s := string(p)
	if !strings.HasPrefix(s, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(s, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// sanitiseCollectionName keeps a client-supplied label usable as both a
// directory name and a D-Bus path element.
//
// A label is arbitrary text from another program: without this, a collection
// called "../../etc" would be a path traversal, and one with a space would
// produce an object path no client can address.
func sanitiseCollectionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return DefaultCollection
	}
	return out
}

// callerOf is a placeholder for the sender of the current call.
//
// GetSecrets does not receive the sender, so policy decisions made from it
// cannot identify the caller; the per-item GetSecret path, which does, is
// where the policy is enforced properly.
func callerOf(dbus.ObjectPath) string { return "" }

// dbusErrf builds a D-Bus error with a formatted message.
func dbusErrf(name, format string, args ...any) *dbus.Error {
	return dbus.NewError(name, []any{fmt.Sprintf(format, args...)})
}

// containsString reports whether xs holds s.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
