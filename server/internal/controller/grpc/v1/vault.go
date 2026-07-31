package v1

import (
	"context"
	"io"

	binpassv1 "github.com/71g3pf4c3/binpass/api/gen/v1"
	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/71g3pf4c3/binpass/server/internal/usecase"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maxChunk is the maximum ciphertext chunk size streamed per message.
const maxChunk = 1 << 20

// VaultController adapts the Vault gRPC service to the VaultUseCase.
type VaultController struct {
	binpassv1.UnimplementedVaultServer
	// uc is the vault use case.
	uc *usecase.VaultUseCase
}

// NewVaultController builds a VaultController.
func NewVaultController(uc *usecase.VaultUseCase) *VaultController {
	return &VaultController{uc: uc}
}

// requireSession returns the caller's session or an Unauthenticated error.
func requireSession(ctx context.Context) (entity.Session, error) {
	sess, ok := sessionFrom(ctx)
	if !ok {
		return entity.Session{}, status.Error(codes.Unauthenticated, "no session")
	}
	return sess, nil
}

// GetManifest returns the caller's latest signed manifest.
func (c *VaultController) GetManifest(ctx context.Context, _ *binpassv1.GetManifestRequest) (*binpassv1.SignedManifest, error) {
	sess, err := requireSession(ctx)
	if err != nil {
		return nil, err
	}
	m, err := c.uc.GetManifest(ctx, sess.UserID)
	if err != nil {
		return nil, toStatus(err)
	}
	return &binpassv1.SignedManifest{
		Manifest:   m.Blob,
		Signature:  m.Signature,
		PublicKey:  m.PublicKey,
		Generation: m.Generation,
	}, nil
}

// CommitManifest commits a new manifest under compare-and-swap.
func (c *VaultController) CommitManifest(ctx context.Context, req *binpassv1.CommitManifestRequest) (*binpassv1.CommitManifestResponse, error) {
	sess, err := requireSession(ctx)
	if err != nil {
		return nil, err
	}
	sm := req.GetManifest()
	if sm == nil {
		return nil, status.Error(codes.InvalidArgument, "missing manifest")
	}
	m := entity.Manifest{
		Blob:      sm.GetManifest(),
		Signature: sm.GetSignature(),
		PublicKey: sm.GetPublicKey(),
	}
	gen, err := c.uc.CommitManifest(ctx, sess.UserID, sess.DeviceID, m, req.GetExpectGeneration())
	if err != nil {
		return nil, toStatus(err)
	}
	return &binpassv1.CommitManifestResponse{Generation: gen}, nil
}

// HasObjects reports which object IDs already exist.
func (c *VaultController) HasObjects(ctx context.Context, req *binpassv1.ObjectIDs) (*binpassv1.ObjectPresence, error) {
	sess, err := requireSession(ctx)
	if err != nil {
		return nil, err
	}
	present, err := c.uc.HasObjects(ctx, sess.UserID, req.GetIds())
	if err != nil {
		return nil, toStatus(err)
	}
	return &binpassv1.ObjectPresence{Present: present}, nil
}

// PutObject receives a ciphertext object as a chunk stream.
func (c *VaultController) PutObject(stream binpassv1.Vault_PutObjectServer) error {
	ctx := stream.Context()
	sess, err := requireSession(ctx)
	if err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "empty upload")
	}
	header := first.GetHeader()
	if header == nil {
		return status.Error(codes.InvalidArgument, "first message must be a header")
	}

	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		var perr error
		for {
			msg, rerr := stream.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				perr = rerr
				break
			}
			if data := msg.GetData(); len(data) > 0 {
				if _, werr := pw.Write(data); werr != nil {
					perr = werr
					break
				}
			}
		}
		pw.CloseWithError(perr)
		errc <- perr
	}()

	obj, err := c.uc.PutObject(ctx, sess.UserID, header.GetOid(), header.GetTotalSize(), pr)
	if err != nil {
		pr.CloseWithError(err)
		return toStatus(err)
	}
	if rerr := <-errc; rerr != nil {
		return status.Error(codes.Internal, "upload stream error")
	}
	return stream.SendAndClose(&binpassv1.PutObjectResponse{Oid: obj.OID, Size: obj.Size})
}

// GetObject streams a ciphertext object back to the caller.
func (c *VaultController) GetObject(req *binpassv1.GetObjectRequest, stream binpassv1.Vault_GetObjectServer) error {
	ctx := stream.Context()
	sess, err := requireSession(ctx)
	if err != nil {
		return err
	}
	rc, err := c.uc.GetObject(ctx, sess.UserID, req.GetOid())
	if err != nil {
		return toStatus(err)
	}
	defer rc.Close()

	buf := make([]byte, maxChunk)
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			if serr := stream.Send(&binpassv1.ObjectChunk{Data: buf[:n]}); serr != nil {
				return serr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return status.Error(codes.Internal, "read object")
		}
	}
}

// Watch streams vault change events until the client disconnects.
func (c *VaultController) Watch(req *binpassv1.WatchRequest, stream binpassv1.Vault_WatchServer) error {
	ctx := stream.Context()
	sess, err := requireSession(ctx)
	if err != nil {
		return err
	}
	ch, err := c.uc.Watch(ctx, sess.UserID, req.GetSinceGeneration())
	if err != nil {
		return toStatus(err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if serr := stream.Send(&binpassv1.ChangeEvent{
				Generation: ev.Generation,
				DeviceId:   ev.DeviceID,
				At:         timestamppb.New(ev.At),
			}); serr != nil {
				return serr
			}
		}
	}
}
