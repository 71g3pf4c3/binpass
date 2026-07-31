package remote

import (
	"context"
	"errors"
	"fmt"
	"io"

	binpassv1 "github.com/71g3pf4c3/binpass/server/gen/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// chunkSize is the ciphertext upload chunk size.
const chunkSize = 1 << 20

// TokenSource supplies the current access token for authenticated calls.
type TokenSource interface {
	// Token returns a valid access token.
	Token(ctx context.Context) (string, error)
}

// GRPCRemote is the gRPC implementation of Remote against binpassd.
type GRPCRemote struct {
	// conn is the underlying gRPC connection.
	conn *grpc.ClientConn
	// vault is the generated Vault client.
	vault binpassv1.VaultClient
	// tokens supplies bearer tokens.
	tokens TokenSource
}

// DialGRPC connects to a binpassd gRPC endpoint. For TLS, pass suitable dial
// options; the default here uses an insecure transport for local testing.
func DialGRPC(target string, tokens TokenSource, opts ...grpc.DialOption) (*GRPCRemote, error) {
	if len(opts) == 0 {
		opts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("remote: dial: %w", err)
	}
	return &GRPCRemote{conn: conn, vault: binpassv1.NewVaultClient(conn), tokens: tokens}, nil
}

// authCtx attaches the bearer token to the outgoing context.
func (r *GRPCRemote) authCtx(ctx context.Context) (context.Context, error) {
	if r.tokens == nil {
		return ctx, nil
	}
	tok, err := r.tokens.Token(ctx)
	if err != nil {
		return ctx, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok), nil
}

// Manifest returns the current signed manifest.
func (r *GRPCRemote) Manifest(ctx context.Context) (*SignedManifest, error) {
	ctx, err := r.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.vault.GetManifest(ctx, &binpassv1.GetManifestRequest{})
	if err != nil {
		return nil, mapErr(err)
	}
	return &SignedManifest{
		Manifest:   resp.GetManifest(),
		Signature:  resp.GetSignature(),
		PublicKey:  resp.GetPublicKey(),
		Generation: resp.GetGeneration(),
	}, nil
}

// CommitManifest commits m under compare-and-swap.
func (r *GRPCRemote) CommitManifest(ctx context.Context, m *SignedManifest, expect uint64) (uint64, error) {
	ctx, err := r.authCtx(ctx)
	if err != nil {
		return 0, err
	}
	resp, err := r.vault.CommitManifest(ctx, &binpassv1.CommitManifestRequest{
		Manifest: &binpassv1.SignedManifest{
			Manifest:   m.Manifest,
			Signature:  m.Signature,
			PublicKey:  m.PublicKey,
			Generation: m.Generation,
		},
		ExpectGeneration: expect,
	})
	if err != nil {
		return 0, mapErr(err)
	}
	return resp.GetGeneration(), nil
}

// HasObjects reports which object IDs already exist.
func (r *GRPCRemote) HasObjects(ctx context.Context, ids []string) (map[string]bool, error) {
	ctx, err := r.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.vault.HasObjects(ctx, &binpassv1.ObjectIDs{Ids: ids})
	if err != nil {
		return nil, mapErr(err)
	}
	return resp.GetPresent(), nil
}

// PutObject streams a ciphertext object to the server.
func (r *GRPCRemote) PutObject(ctx context.Context, oid string, size int64, src io.Reader) error {
	ctx, err := r.authCtx(ctx)
	if err != nil {
		return err
	}
	stream, err := r.vault.PutObject(ctx)
	if err != nil {
		return mapErr(err)
	}
	if err := stream.Send(&binpassv1.PutObjectChunk{
		Payload: &binpassv1.PutObjectChunk_Header{
			Header: &binpassv1.ObjectHeader{Oid: oid, TotalSize: size},
		},
	}); err != nil {
		return mapErr(err)
	}
	buf := make([]byte, chunkSize)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if serr := stream.Send(&binpassv1.PutObjectChunk{
				Payload: &binpassv1.PutObjectChunk_Data{Data: buf[:n]},
			}); serr != nil {
				return mapErr(serr)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("remote: read source: %w", rerr)
		}
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		return mapErr(err)
	}
	return nil
}

// GetObject downloads a ciphertext object as a streaming reader.
func (r *GRPCRemote) GetObject(ctx context.Context, oid string) (io.ReadCloser, error) {
	ctx, err := r.authCtx(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := r.vault.GetObject(ctx, &binpassv1.GetObjectRequest{Oid: oid})
	if err != nil {
		return nil, mapErr(err)
	}
	return &objectReader{stream: stream}, nil
}

// Close closes the gRPC connection.
func (r *GRPCRemote) Close() error { return r.conn.Close() }

// mapErr converts gRPC status codes to package-level errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.FailedPrecondition {
		return ErrConflict
	}
	return err
}

// objectReader adapts a server-streaming download to io.ReadCloser.
type objectReader struct {
	// stream is the underlying gRPC download stream.
	stream grpc.ServerStreamingClient[binpassv1.ObjectChunk]
	// buf holds bytes not yet consumed by Read.
	buf []byte
	// err is a sticky terminal error.
	err error
}

// Read returns ciphertext bytes, fetching more chunks as needed.
func (o *objectReader) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.err != nil {
			return 0, o.err
		}
		chunk, err := o.stream.Recv()
		if err != nil {
			o.err = err
			if errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, mapErr(err)
		}
		o.buf = chunk.GetData()
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// Close releases the reader; the stream is drained by the connection.
func (o *objectReader) Close() error { return nil }
