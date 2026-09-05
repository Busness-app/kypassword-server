package users

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already taken")
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User represents a KyPassword user record.
//
// It holds no authentication material of any kind. KySignOn authenticates; this server
// only records who an identity is and what they may do. The master password never
// reaches it, not even as a derived verifier — it is the client-side secret that unwraps
// the vault key envelope, and nothing else.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Role        Role      `json:"role"`
	Active      bool      `json:"active"`
	SCIMDeleted bool      `json:"scimDeleted,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`

	// KySignOn linkage. SSOSub is the OIDC subject and the only key an identity is
	// matched on; the rest are attributes carried along with it.
	SSOSub      string `json:"ssoSub,omitempty"`
	SSOUsername string `json:"ssoUsername,omitempty"`
	SSOEmail    string `json:"ssoEmail,omitempty"`
	SSOLinkedAt int64  `json:"ssoLinkedAt,omitempty"`
}

// Public returns a safe representation of the user for APIs.
type Public struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        Role   `json:"role"`
	Active      bool   `json:"active"`
	SSOSub      string `json:"ssoSub,omitempty"`
	SSOUsername string `json:"ssoUsername,omitempty"`
	SSOEmail    string `json:"ssoEmail,omitempty"`
	SSOLinkedAt int64  `json:"ssoLinkedAt,omitempty"`
}

func (u User) Public() Public {
	return Public{
		ID:          u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Active:      u.Active,
		SSOSub:      u.SSOSub,
		SSOUsername: u.SSOUsername,
		SSOEmail:    u.SSOEmail,
		SSOLinkedAt: u.SSOLinkedAt,
	}
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	users    map[string]User   // key: ID
	byName   map[string]string // lowercase username -> ID
	bySSOSub map[string]string // SSOSub -> ID
}

// NewStore loads or creates a user store at the given path.
//
// A users.json written by an older build still carries passwordHash, authSalt,
// authIterations, recoveryHash and mustChangePassword. encoding/json ignores keys the
// struct no longer declares, so such a file loads cleanly and the retired fields are
// erased from disk on the first save. There is nothing to migrate to.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir users dir: %w", err)
	}

	filePath := filepath.Join(dir, "users.json")
	s := &Store{
		filePath: filePath,
		users:    make(map[string]User),
		byName:   make(map[string]string),
		bySSOSub: make(map[string]string),
	}

	data, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}

	var list []User
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	for _, u := range list {
		s.users[u.ID] = u
		s.byName[strings.ToLower(u.Username)] = u.ID
		if u.SSOSub != "" {
			s.bySSOSub[u.SSOSub] = u.ID
		}
	}

	return s, nil
}

func (s *Store) saveLocked() error {
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := s.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpFile, s.filePath)
}

// CreateSSOUser provisions an active local account for a KySignOn identity at sign-in.
func (s *Store) CreateSSOUser(username string, role Role, ssoSub, ssoUsername, ssoEmail string) (User, error) {
	return s.CreateDirectoryUser(username, role, ssoSub, ssoUsername, ssoEmail, true)
}

// CreateDirectoryUser persists the requested active state in the initial write.
func (s *Store) CreateDirectoryUser(username string, role Role, ssoSub, ssoUsername, ssoEmail string, active bool) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lower := strings.ToLower(strings.TrimSpace(username))
	if lower == "" {
		return User{}, errors.New("empty username")
	}
	if _, exists := s.byName[lower]; exists {
		return User{}, ErrUsernameTaken
	}
	if _, exists := s.bySSOSub[ssoSub]; exists {
		return s.users[s.bySSOSub[ssoSub]], nil
	}

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	u := User{
		ID:          id,
		Username:    strings.TrimSpace(username),
		Role:        role,
		Active:      active,
		CreatedAt:   now,
		UpdatedAt:   now,
		SSOSub:      ssoSub,
		SSOUsername: ssoUsername,
		SSOEmail:    ssoEmail,
		SSOLinkedAt: now.Unix(),
	}

	s.users[id] = u
	s.byName[lower] = id
	s.bySSOSub[ssoSub] = id

	if err := s.saveLocked(); err != nil {
		delete(s.users, id)
		delete(s.byName, lower)
		delete(s.bySSOSub, ssoSub)
		return User{}, err
	}

	return u, nil
}

// Get finds a user by ID.
func (s *Store) Get(id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.users[id]
	if !exists {
		return User{}, ErrNotFound
	}
	return u, nil
}

// GetByUsername finds a user by username (case-insensitive).
func (s *Store) GetByUsername(username string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byName[strings.ToLower(strings.TrimSpace(username))]
	if !exists {
		return User{}, ErrNotFound
	}
	return s.users[id], nil
}

// GetBySSOSub finds a user by their SSO subject identifier.
func (s *Store) GetBySSOSub(sub string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.bySSOSub[sub]
	if !exists {
		return User{}, ErrNotFound
	}
	return s.users[id], nil
}

// List returns all users.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()

	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	return list
}

// Snapshot returns the complete durable user document while writes are stopped.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	return json.MarshalIndent(list, "", "  ")
}

// LinkSSO attaches an SSO identity to a user.
func (s *Store) LinkSSO(id, sub, username, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	if oldID, taken := s.bySSOSub[sub]; taken && oldID != id {
		return errors.New("SSO subject is already linked to another account")
	}

	if u.SSOSub != "" {
		delete(s.bySSOSub, u.SSOSub)
	}

	u.SSOSub = sub
	u.SSOUsername = username
	u.SSOEmail = email
	u.SSOLinkedAt = time.Now().UTC().Unix()
	u.UpdatedAt = time.Now().UTC()

	s.users[id] = u
	s.bySSOSub[sub] = id
	return s.saveLocked()
}

// SetRole updates a user's role.
func (s *Store) SetRole(id string, role Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	u.Role = role
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	return s.saveLocked()
}

// Deactivate disables a user.
func (s *Store) Deactivate(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	u.Active = false
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	return s.saveLocked()
}

// Reactivate enables a user.
func (s *Store) Reactivate(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	u.Active = true
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	return s.saveLocked()
}

// Paper recovery is deliberately absent. It used to verify a server-side hash and start a
// session, which under SSO-only would be a second way to authenticate. The capability
// itself is unharmed: the recovery-wrapped key envelope lives in vault metadata and is
// unwrapped client-side, after a KySignOn session already exists. It unlocks the vault,
// not the site.

// UpdateDirectory atomically applies one complete, validated directory resource.
func (s *Store) UpdateDirectory(id string, role Role, active bool, username, email string, deleted bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[id]
	if !ok {
		return ErrNotFound
	}
	u := old
	u.Role, u.Active, u.SSOUsername, u.SSOEmail, u.SCIMDeleted = role, active, username, email, deleted
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	if err := s.saveLocked(); err != nil {
		s.users[id] = old
		return err
	}
	return nil
}
