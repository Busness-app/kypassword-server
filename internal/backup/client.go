package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Busness-app/ky-primitives/recoverykey"
)

type Client struct{ http *http.Client }

func NewClient() *Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if publicIP(ip) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, errors.New("recovery host resolves only to private or reserved addresses")
	}}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }
	return &Client{http: httpClient}
}

var blockedNetworks = mustNetworks(
	"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96",
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)

func mustNetworks(raw ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raw))
	for _, value := range raw {
		_, network, _ := net.ParseCIDR(value)
		out = append(out, network)
	}
	return out
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func endpoint(server, path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: must be a plain HTTPS origin", ErrInvalidURL)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return "", fmt.Errorf("%w: cannot target a private or reserved address", ErrInvalidURL)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

type PairingResult struct {
	Token string
	Key   RecoveryKey
}

type RecoveryClient interface {
	Depositor
	Claim(context.Context, string, string) (PairingResult, error)
}

func (c *Client) Claim(ctx context.Context, server, code string) (PairingResult, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return PairingResult{}, errors.New("pairing code must be six digits")
	}
	u, err := endpoint(server, "/api/pairing/claim")
	if err != nil {
		return PairingResult{}, err
	}
	body, _ := json.Marshal(map[string]string{"pairing_code": code, "service_name": ServiceName, "app_name": AppName})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return PairingResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return PairingResult{}, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PairingResult{}, fmt.Errorf("%w: claim rejected (%d): %s", ErrRemote, resp.StatusCode, remoteMessage(resp.Body))
	}
	var out struct {
		APIToken          string `json:"api_token"`
		RecoveryPublicKey string `json:"recovery_public_key"`
		Threshold         int    `json:"threshold"`
		TotalShares       int    `json:"total_shares"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return PairingResult{}, fmt.Errorf("%w: invalid claim response", ErrRemote)
	}
	raw, err := base64.StdEncoding.DecodeString(out.RecoveryPublicKey)
	if err != nil {
		return PairingResult{}, fmt.Errorf("%w: invalid recovery public key", ErrRemote)
	}
	public, err := recoverykey.ParsePublicKey(raw)
	if err != nil || out.APIToken == "" || !validTopology(out.Threshold, out.TotalShares) {
		return PairingResult{}, fmt.Errorf("%w: incomplete claim response", ErrRemote)
	}
	return PairingResult{Token: out.APIToken, Key: RecoveryKey{Public: public, Threshold: out.Threshold, TotalShares: out.TotalShares}}, nil
}

type Depositor interface {
	Deposit(context.Context, string, string, []byte) (Receipt, error)
}

func (c *Client) Deposit(ctx context.Context, server, token string, raw []byte) (Receipt, error) {
	u, err := endpoint(server, "/api/backup/deposit")
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return Receipt{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	upload := *c.http
	upload.Timeout = 0
	resp, err := upload.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("%w: deposit rejected (%d): %s", ErrRemote, resp.StatusCode, remoteMessage(resp.Body))
	}
	var receipt Receipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("%w: invalid deposit receipt", ErrRemote)
	}
	sum := sha256.Sum256(raw)
	if receipt.CapsuleID == "" || receipt.Digest != hex.EncodeToString(sum[:]) || receipt.SizeBytes != int64(len(raw)) {
		return Receipt{}, fmt.Errorf("%w: receipt does not match deposited capsule", ErrRemote)
	}
	return receipt, nil
}

func remoteMessage(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return AuditSafe(string(b))
}

func AuditSafe(value string) string {
	var out strings.Builder
	for _, r := range value {
		if out.Len() >= 200 {
			out.WriteString("...")
			break
		}
		if r == '\n' || r == '\t' {
			out.WriteByte(' ')
		} else if unicode.IsPrint(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}
