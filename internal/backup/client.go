package backup

import (
	"context"
	"fmt"
	"github.com/Busness-app/ky-primitives/recoveryclient"
)

type Client struct {
	*recoveryclient.Client
	allowPrivate bool
}

func NewClient(allowPrivate bool) *Client {
	return &Client{Client: recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: allowPrivate}), allowPrivate: allowPrivate}
}

type PairingResult struct {
	Token string
	Key   RecoveryKey
}
type Depositor = recoveryclient.Depositor
type RecoveryClient interface {
	Claim(context.Context, string, string) (PairingResult, error)
	Depositor
}

func (c *Client) Claim(ctx context.Context, server, code string) (PairingResult, error) {
	if err := ValidateURL(server, c.allowPrivate); err != nil {
		return PairingResult{}, fmt.Errorf("%w: use KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY only for an intended private HTTPS host: %s", ErrInvalidURL, AuditSafe(err.Error()))
	}
	r, err := c.ClaimPairing(ctx, server, code, ServiceName, AppName)
	if err != nil {
		return PairingResult{}, fmt.Errorf("%w: pairing claim failed", ErrRemote)
	}
	return PairingResult{Token: r.APIToken, Key: r.Key}, nil
}
func AuditSafe(s string) string { return recoveryclient.AuditSafe(s) }

// ValidateURL delegates address policy to recoveryclient, including DNS-time checks.
func ValidateURL(raw string, allowPrivate bool) error {
	return recoveryclient.ValidateURL(raw, allowPrivate)
}
func (c *Client) Deposit(ctx context.Context, server, token string, raw []byte) (Receipt, error) {
	if err := ValidateURL(server, c.allowPrivate); err != nil {
		return Receipt{}, fmt.Errorf("%w: invalid recovery destination", ErrInvalidURL)
	}
	r, err := c.Client.Deposit(ctx, server, token, raw)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: remote deposit failed or receipt did not verify", ErrRemote)
	}
	return r, nil
}
