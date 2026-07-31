package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/71g3pf4c3/binpass/server/pkg/argon2"
	"github.com/google/uuid"
)

// Tokens is the result of a successful auth operation.
type Tokens struct {
	// AccessToken is a short-lived signed access token.
	AccessToken string
	// RefreshToken is a long-lived opaque refresh token (plaintext, returned
	// once to the client; only its hash is stored).
	RefreshToken string
	// UserSalt is the per-user salt for client key derivation.
	UserSalt []byte
	// DeviceID is the authenticated device.
	DeviceID string
	// AccessExpiresAt is the access-token expiry.
	AccessExpiresAt time.Time
}

// AuthUseCase implements registration, login, token rotation, and device
// management.
type AuthUseCase struct {
	// users, devices, tokens are the persistence ports.
	users   UserRepo
	devices DeviceRepo
	tokens  TokenRepo
	// issuer signs access tokens.
	issuer TokenIssuer
	// hasher hashes auth secrets.
	hasher Hasher
	// refreshTTL is the refresh-token lifetime.
	refreshTTL time.Duration
}

// NewAuth builds an AuthUseCase.
func NewAuth(users UserRepo, devices DeviceRepo, tokens TokenRepo, issuer TokenIssuer, hasher Hasher, refreshTTL time.Duration) *AuthUseCase {
	return &AuthUseCase{
		users:      users,
		devices:    devices,
		tokens:     tokens,
		issuer:     issuer,
		hasher:     hasher,
		refreshTTL: refreshTTL,
	}
}

// Register creates a new account, enrols the first device, and returns tokens
// plus the freshly generated user salt.
func (uc *AuthUseCase) Register(ctx context.Context, login, authSecret, deviceName string) (*Tokens, error) {
	if login == "" || authSecret == "" {
		return nil, entity.ErrInvalidCredentials
	}
	hash, err := uc.hasher.Hash(authSecret)
	if err != nil {
		return nil, fmt.Errorf("auth: hash: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("auth: salt: %w", err)
	}
	u := entity.User{
		ID:        uuid.NewString(),
		Login:     login,
		AuthHash:  hash,
		UserSalt:  salt,
		CreatedAt: time.Now(),
	}
	if err := uc.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return uc.enrollAndIssue(ctx, u, deviceName)
}

// Login authenticates an existing user and enrols the requesting device.
func (uc *AuthUseCase) Login(ctx context.Context, login, authSecret, deviceName string) (*Tokens, error) {
	u, err := uc.users.ByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			return nil, entity.ErrInvalidCredentials
		}
		return nil, err
	}
	ok, err := argon2.Verify(authSecret, u.AuthHash)
	if err != nil {
		return nil, fmt.Errorf("auth: verify: %w", err)
	}
	if !ok {
		return nil, entity.ErrInvalidCredentials
	}
	return uc.enrollAndIssue(ctx, u, deviceName)
}

// enrollAndIssue creates a device and issues a fresh token pair.
func (uc *AuthUseCase) enrollAndIssue(ctx context.Context, u entity.User, deviceName string) (*Tokens, error) {
	now := time.Now()
	d := entity.Device{
		ID:         uuid.NewString(),
		UserID:     u.ID,
		Name:       deviceName,
		CreatedAt:  now,
		LastSeenAt: now,
	}
	if err := uc.devices.Create(ctx, d); err != nil {
		return nil, err
	}
	return uc.issueTokens(ctx, u, d.ID)
}

// issueTokens signs an access token and stores a new refresh token.
func (uc *AuthUseCase) issueTokens(ctx context.Context, u entity.User, deviceID string) (*Tokens, error) {
	access, exp, err := uc.issuer.Issue(u.ID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("auth: issue: %w", err)
	}
	refresh, err := randomToken()
	if err != nil {
		return nil, err
	}
	rt := entity.RefreshToken{
		ID:        uuid.NewString(),
		DeviceID:  deviceID,
		UserID:    u.ID,
		TokenHash: hashToken(refresh),
		ExpiresAt: time.Now().Add(uc.refreshTTL),
	}
	if err := uc.tokens.Create(ctx, rt); err != nil {
		return nil, err
	}
	return &Tokens{
		AccessToken:     access,
		RefreshToken:    refresh,
		UserSalt:        u.UserSalt,
		DeviceID:        deviceID,
		AccessExpiresAt: exp,
	}, nil
}

// Refresh rotates a refresh token. Reuse of an already-rotated token revokes
// the entire device chain (theft detection).
func (uc *AuthUseCase) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	rt, err := uc.tokens.ByHash(ctx, hashToken(refreshToken))
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			return nil, entity.ErrTokenInvalid
		}
		return nil, err
	}
	if rt.Revoked || time.Now().After(rt.ExpiresAt) {
		return nil, entity.ErrTokenInvalid
	}
	if rt.UsedAt != nil {
		// Reuse of a rotated token: revoke the whole chain.
		_ = uc.tokens.RevokeByDevice(ctx, rt.DeviceID)
		return nil, entity.ErrTokenInvalid
	}
	if err := uc.tokens.MarkUsed(ctx, rt.ID, time.Now()); err != nil {
		return nil, err
	}
	u, err := uc.users.ByID(ctx, rt.UserID)
	if err != nil {
		return nil, err
	}
	_ = uc.devices.Touch(ctx, rt.DeviceID, time.Now())
	return uc.issueTokens(ctx, u, rt.DeviceID)
}

// Logout revokes the given refresh token.
func (uc *AuthUseCase) Logout(ctx context.Context, refreshToken string) error {
	rt, err := uc.tokens.ByHash(ctx, hashToken(refreshToken))
	if err != nil {
		if errors.Is(err, entity.ErrNotFound) {
			return nil
		}
		return err
	}
	return uc.tokens.Revoke(ctx, rt.ID)
}

// ListDevices returns the user's enrolled devices.
func (uc *AuthUseCase) ListDevices(ctx context.Context, userID string) ([]entity.Device, error) {
	return uc.devices.ListByUser(ctx, userID)
}

// RevokeDevice revokes a device (verifying ownership) and its token chain.
func (uc *AuthUseCase) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	d, err := uc.devices.ByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if d.UserID != userID {
		return entity.ErrPermissionDenied
	}
	if err := uc.devices.Revoke(ctx, userID, deviceID, time.Now()); err != nil {
		return err
	}
	return uc.tokens.RevokeByDevice(ctx, deviceID)
}

// randomToken returns a 32-byte URL-safe random token as hex.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the hex SHA-256 of a token for storage/lookup.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
