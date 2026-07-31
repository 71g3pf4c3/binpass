package usecase

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
)

// fakeUserRepo is an in-memory UserRepo.
type fakeUserRepo struct {
	mu    sync.Mutex
	byID  map[string]entity.User
	byLog map[string]entity.User
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byID: map[string]entity.User{}, byLog: map[string]entity.User{}}
}

func (r *fakeUserRepo) Create(_ context.Context, u entity.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byLog[u.Login]; ok {
		return entity.ErrLoginTaken
	}
	r.byID[u.ID] = u
	r.byLog[u.Login] = u
	return nil
}

func (r *fakeUserRepo) ByLogin(_ context.Context, login string) (entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byLog[login]
	if !ok {
		return entity.User{}, entity.ErrNotFound
	}
	return u, nil
}

func (r *fakeUserRepo) ByID(_ context.Context, id string) (entity.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return entity.User{}, entity.ErrNotFound
	}
	return u, nil
}

// fakeDeviceRepo is an in-memory DeviceRepo.
type fakeDeviceRepo struct {
	mu   sync.Mutex
	byID map[string]entity.Device
}

func newFakeDeviceRepo() *fakeDeviceRepo {
	return &fakeDeviceRepo{byID: map[string]entity.Device{}}
}

func (r *fakeDeviceRepo) Create(_ context.Context, d entity.Device) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[d.ID] = d
	return nil
}

func (r *fakeDeviceRepo) ByID(_ context.Context, id string) (entity.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d, ok := r.byID[id]
	if !ok {
		return entity.Device{}, entity.ErrNotFound
	}
	return d, nil
}

func (r *fakeDeviceRepo) ListByUser(_ context.Context, userID string) ([]entity.Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entity.Device
	for _, d := range r.byID {
		if d.UserID == userID {
			out = append(out, d)
		}
	}
	return out, nil
}

func (r *fakeDeviceRepo) Revoke(_ context.Context, userID, deviceID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.byID[deviceID]
	d.RevokedAt = &at
	r.byID[deviceID] = d
	return nil
}

func (r *fakeDeviceRepo) Touch(_ context.Context, deviceID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.byID[deviceID]
	d.LastSeenAt = at
	r.byID[deviceID] = d
	return nil
}

// fakeTokenRepo is an in-memory TokenRepo.
type fakeTokenRepo struct {
	mu     sync.Mutex
	byHash map[string]entity.RefreshToken
	byID   map[string]string // id -> hash
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{byHash: map[string]entity.RefreshToken{}, byID: map[string]string{}}
}

func (r *fakeTokenRepo) Create(_ context.Context, t entity.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byHash[t.TokenHash] = t
	r.byID[t.ID] = t.TokenHash
	return nil
}

func (r *fakeTokenRepo) ByHash(_ context.Context, hash string) (entity.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.byHash[hash]
	if !ok {
		return entity.RefreshToken{}, entity.ErrNotFound
	}
	return t, nil
}

func (r *fakeTokenRepo) MarkUsed(_ context.Context, id string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.byID[id]
	t := r.byHash[h]
	t.UsedAt = &at
	r.byHash[h] = t
	return nil
}

func (r *fakeTokenRepo) Revoke(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.byID[id]
	t := r.byHash[h]
	t.Revoked = true
	r.byHash[h] = t
	return nil
}

func (r *fakeTokenRepo) RevokeByDevice(_ context.Context, deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, t := range r.byHash {
		if t.DeviceID == deviceID {
			t.Revoked = true
			r.byHash[h] = t
		}
	}
	return nil
}

// fakeIssuer issues predictable tokens.
type fakeIssuer struct{}

func (fakeIssuer) Issue(userID, deviceID string) (string, time.Time, error) {
	return "access-" + userID + "-" + deviceID, time.Now().Add(time.Hour), nil
}

// plainHasher hashes by prefixing, so Login's argon2.Verify path is exercised
// separately; here we only need deterministic hashing for Register tests.
type plainHasher struct{}

func (plainHasher) Hash(secret string) (string, error) { return "hash:" + secret, nil }

// fakeManifestRepo is an in-memory ManifestRepo with CAS semantics.
type fakeManifestRepo struct {
	mu   sync.Mutex
	byUG map[string]map[uint64]entity.Manifest
}

func newFakeManifestRepo() *fakeManifestRepo {
	return &fakeManifestRepo{byUG: map[string]map[uint64]entity.Manifest{}}
}

func (r *fakeManifestRepo) Latest(_ context.Context, userID string) (entity.Manifest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	gens := r.byUG[userID]
	if len(gens) == 0 {
		return entity.Manifest{}, entity.ErrNotFound
	}
	var max uint64
	for g := range gens {
		if g > max {
			max = g
		}
	}
	return gens[max], nil
}

func (r *fakeManifestRepo) InsertIfNext(_ context.Context, m entity.Manifest, expect uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	gens := r.byUG[m.UserID]
	var cur uint64
	for g := range gens {
		if g > cur {
			cur = g
		}
	}
	if cur != expect {
		return entity.ErrGenerationMismatch
	}
	if gens == nil {
		gens = map[uint64]entity.Manifest{}
		r.byUG[m.UserID] = gens
	}
	gens[m.Generation] = m
	return nil
}

// fakeObjectRepo is an in-memory ObjectRepo.
type fakeObjectRepo struct {
	mu   sync.Mutex
	objs map[string]entity.Object // key: user/oid
}

func newFakeObjectRepo() *fakeObjectRepo {
	return &fakeObjectRepo{objs: map[string]entity.Object{}}
}

func (r *fakeObjectRepo) Exists(_ context.Context, userID string, oids []string) (map[string]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]bool{}
	for _, oid := range oids {
		_, ok := r.objs[userID+"/"+oid]
		out[oid] = ok
	}
	return out, nil
}

func (r *fakeObjectRepo) Upsert(_ context.Context, o entity.Object) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objs[o.UserID+"/"+o.OID] = o
	return nil
}

func (r *fakeObjectRepo) Get(_ context.Context, userID, oid string) (entity.Object, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.objs[userID+"/"+oid]
	if !ok {
		return entity.Object{}, entity.ErrNotFound
	}
	return o, nil
}

// fakeBlobStore is an in-memory BlobStore.
type fakeBlobStore struct {
	mu    sync.Mutex
	blobs map[string][]byte
}

func newFakeBlobStore() *fakeBlobStore {
	return &fakeBlobStore{blobs: map[string][]byte{}}
}

func (b *fakeBlobStore) Put(_ context.Context, ref string, r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	b.mu.Lock()
	b.blobs[ref] = data
	b.mu.Unlock()
	return int64(len(data)), nil
}

func (b *fakeBlobStore) Get(_ context.Context, ref string) (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.blobs[ref]
	if !ok {
		return nil, entity.ErrNotFound
	}
	return io.NopCloser(readerBytes(data)), nil
}

func (b *fakeBlobStore) Delete(_ context.Context, ref string) error {
	b.mu.Lock()
	delete(b.blobs, ref)
	b.mu.Unlock()
	return nil
}

// readerBytes returns an io.Reader over b.
func readerBytes(b []byte) io.Reader { return &byteReader{b: b} }

type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// noopBus discards published events and never sends.
type noopBus struct{}

func (noopBus) Publish(string, entity.ChangeEvent) {}
func (noopBus) Subscribe(ctx context.Context, _ string) <-chan entity.ChangeEvent {
	ch := make(chan entity.ChangeEvent)
	go func() { <-ctx.Done(); close(ch) }()
	return ch
}
