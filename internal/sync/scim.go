// Package sync receives account replication from KySignOn.
//
// KySignOn's sync engine POSTs a bare SCIM 2.0 User resource and carries the event type,
// timestamp and signature in headers. This package parses exactly that, and nothing else:
// the wire format is dictated by the sender, which is already deployed.
package sync

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SCIMUser is the subset of a SCIM User resource KyPassword acts on.
type SCIMUser struct {
	// ID is the KySignOn user ID, which is also the OIDC `sub`. It is the only key an
	// account is ever matched on.
	ID       string
	Username string
	Email    string
	Role     string
	Active   bool
}

type scimResource struct {
	ID       string `json:"id"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
	Emails   []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Roles []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"roles"`
}

// ParseSCIMUser reads a KySignOn SCIM User resource.
func ParseSCIMUser(body []byte) (SCIMUser, error) {
	var res scimResource
	if err := json.Unmarshal(body, &res); err != nil {
		return SCIMUser{}, fmt.Errorf("body is not a SCIM user resource: %w", err)
	}
	if res.ID == "" {
		return SCIMUser{}, errors.New("SCIM resource has no id, so it identifies no account")
	}

	u := SCIMUser{ID: res.ID, Username: res.UserName, Active: res.Active}
	for _, e := range res.Emails {
		if e.Primary || u.Email == "" {
			u.Email = e.Value
		}
	}
	for _, r := range res.Roles {
		if r.Primary || u.Role == "" {
			u.Role = r.Value
		}
	}
	return u, nil
}
