package backup

import (
	"context"
	"fmt"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"net/netip"
	"net/url"
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

// ValidateURL retains KyPassword's refusal of literal documentation addresses.
// The library owns DNS resolution, address pinning, and private/loopback restrictions.
func ValidateURL(raw string, allowPrivate bool) error {
	if err := recoveryclient.ValidateURL(raw, allowPrivate); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
		for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
			if netip.MustParsePrefix(cidr).Contains(ip.Unmap()) {
				return fmt.Errorf("documentation address is not a recovery destination")
			}
		}
	}
	return nil
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
