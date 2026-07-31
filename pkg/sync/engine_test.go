package sync_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"testing"

	"github.com/71g3pf4c3/binpass/pkg/manifest"
	"github.com/71g3pf4c3/binpass/pkg/remote"
	remotemocks "github.com/71g3pf4c3/binpass/pkg/remote/mocks"
	binpasssync "github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// memLocal is an in-memory sync.Local + sync.State used for engine tests.
type memLocal struct {
	storeID  string
	deviceID string
	key      ed25519.PrivateKey
	objects  map[string][]byte // oid -> ciphertext
	tree     map[string]string // path -> oid
	base     *manifest.Manifest
}

func newMemLocal(t *testing.T) *memLocal {
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &memLocal{
		storeID:  "store-1",
		deviceID: "L",
		key:      priv,
		objects:  map[string][]byte{},
		tree:     map[string]string{},
	}
}

// put stores a secret in the in-memory tree.
func (m *memLocal) put(path, content string) {
	oid := manifest.ObjectID([]byte(content))
	m.objects[oid] = []byte(content)
	m.tree[path] = oid
}

func (m *memLocal) StoreID() string  { return m.storeID }
func (m *memLocal) DeviceID() string { return m.deviceID }
func (m *memLocal) SigningKey() (ed25519.PrivateKey, error) {
	return m.key, nil
}

func (m *memLocal) BuildManifest(base *manifest.Manifest) (*manifest.Manifest, error) {
	out := manifest.New(m.storeID)
	if base != nil {
		out.Generation = base.Generation
	}
	for path, oid := range m.tree {
		vv := manifest.VersionVector{m.deviceID: 1}
		if base != nil {
			if prev, ok := base.Entries[path]; ok {
				vv = prev.Version
				if prev.Object != oid {
					vv = manifest.Bump(prev.Version, m.deviceID)
				}
			}
		}
		out.Entries[path] = manifest.Entry{Object: oid, Size: int64(len(m.objects[oid])), Kind: manifest.KindSecret, Version: vv}
	}
	return out, nil
}

func (m *memLocal) ReadObject(id string) ([]byte, error) {
	if b, ok := m.objects[id]; ok {
		return b, nil
	}
	return nil, io.EOF
}

func (m *memLocal) WriteObject(path, id string, ciphertext []byte) error {
	m.objects[id] = ciphertext
	m.tree[path] = id
	return nil
}

func (m *memLocal) ApplyDeletion(path string) error { delete(m.tree, path); return nil }

func (m *memLocal) WriteConflictCopy(path string, ciphertext []byte) (string, error) {
	sib := path + ".conflict"
	oid := manifest.ObjectID(ciphertext)
	m.objects[oid] = ciphertext
	m.tree[sib] = oid
	return sib, nil
}

func (m *memLocal) HasEntry(path string) bool { _, ok := m.tree[path]; return ok }
func (m *memLocal) EntryObject(path string) string {
	return m.tree[path]
}

func (m *memLocal) LoadBase() (*manifest.Manifest, error) { return m.base, nil }
func (m *memLocal) SaveBase(mm *manifest.Manifest) error  { m.base = mm; return nil }

func TestEnginePushToEmptyRemote(t *testing.T) {
	ctrl := gomock.NewController(t)
	local := newMemLocal(t)
	local.put("github.com/alice", "hunter2")

	r := remotemocks.NewMockRemote(ctrl)
	r.EXPECT().Manifest(gomock.Any()).Return(nil, remote.ErrNotFound)
	r.EXPECT().HasObjects(gomock.Any(), gomock.Any()).Return(map[string]bool{}, nil)
	r.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	r.EXPECT().CommitManifest(gomock.Any(), gomock.Any(), uint64(0)).Return(nil)

	eng := binpasssync.NewEngine(local, local)
	report, err := eng.Sync(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, 1, report.Pushed)
	assert.Equal(t, uint64(1), report.Generation)
}

func TestEngineRetriesOnConflict(t *testing.T) {
	ctrl := gomock.NewController(t)
	local := newMemLocal(t)
	local.put("a", "x")

	r := remotemocks.NewMockRemote(ctrl)
	// First attempt: empty remote, commit conflicts.
	gomock.InOrder(
		r.EXPECT().Manifest(gomock.Any()).Return(nil, remote.ErrNotFound),
		r.EXPECT().HasObjects(gomock.Any(), gomock.Any()).Return(map[string]bool{}, nil),
		r.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		r.EXPECT().CommitManifest(gomock.Any(), gomock.Any(), uint64(0)).Return(remote.ErrConflict),
		// Second attempt: still empty, commit succeeds.
		r.EXPECT().Manifest(gomock.Any()).Return(nil, remote.ErrNotFound),
		r.EXPECT().HasObjects(gomock.Any(), gomock.Any()).Return(map[string]bool{}, nil),
		r.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		r.EXPECT().CommitManifest(gomock.Any(), gomock.Any(), uint64(0)).Return(nil),
	)

	eng := binpasssync.NewEngine(local, local)
	report, err := eng.Sync(context.Background(), r)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), report.Generation)
}
