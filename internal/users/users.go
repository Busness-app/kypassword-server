package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already taken")
	ErrInvalidAuth   = errors.New("invalid credentials")
	ErrUserInactive  = errors.New("user account is deactivated")
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User represents a KyPassword user record.
type User struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	Role               Role      `json:"role"`
	Active             bool      `json:"active"`
	PasswordHash       string    `json:"passwordHash"`
	AuthSalt           string    `json:"authSalt"`
	AuthIterations     int       `json:"authIterations"`
	RecoveryHash       string    `json:"recoveryHash,omitempty"`
	MustChangePassword bool      `json:"mustChangePassword"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`

	// SSO Linkage (KySignOn / Authentik / Keycloak)
	SSOSub      string `json:"ssoSub,omitempty"`
	SSOUsername string `json:"ssoUsername,omitempty"`
	SSOEmail    string `json:"ssoEmail,omitempty"`
	SSOLinkedAt int64  `json:"ssoLinkedAt,omitempty"`
}

// Public returns a safe representation of the user for APIs.
type Public struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               Role   `json:"role"`
	Active             bool   `json:"active"`
	MustChangePassword bool   `json:"mustChangePassword"`
	SSOSub             string `json:"ssoSub,omitempty"`
	SSOUsername        string `json:"ssoUsername,omitempty"`
	SSOEmail           string `json:"ssoEmail,omitempty"`
	SSOLinkedAt        int64  `json:"ssoLinkedAt,omitempty"`
}

func (u User) Public() Public {
	return Public{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		Active:             u.Active,
		MustChangePassword: u.MustChangePassword,
		SSOSub:             u.SSOSub,
		SSOUsername:        u.SSOUsername,
		SSOEmail:           u.SSOEmail,
		SSOLinkedAt:        u.SSOLinkedAt,
	}
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	users    map[string]User   // key: ID
	byName   map[string]string // lowercase username -> ID
	bySSOSub map[string]string // SSOSub -> ID
}

// HashPassword hashes a credential using scrypt.
func HashPassword(secret, saltHex string) (string, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", err
	}
	hash, err := scrypt.Key([]byte(secret), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

// NewStore loads or creates a user store at the given path.
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

// Create provisions a new user with password.
func (s *Store) Create(username, password string, role Role) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lower := strings.ToLower(strings.TrimSpace(username))
	if lower == "" {
		return User{}, errors.New("empty username")
	}
	if _, exists := s.byName[lower]; exists {
		return User{}, ErrUsernameTaken
	}

	saltBytes := make([]byte, 16)
	_, _ = rand.Read(saltBytes)
	saltHex := hex.EncodeToString(saltBytes)

	hash, err := HashPassword(password, saltHex)
	if err != nil {
		return User{}, err
	}

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	u := User{
		ID:                 id,
		Username:           strings.TrimSpace(username),
		Role:               role,
		Active:             true,
		PasswordHash:       hash,
		AuthSalt:           saltHex,
		AuthIterations:     600000,
		MustChangePassword: false,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	s.users[id] = u
	s.byName[lower] = id

	if err := s.saveLocked(); err != nil {
		delete(s.users, id)
		delete(s.byName, lower)
		return User{}, err
	}

	return u, nil
}

// CreateSSOUser provisions a new user via SSO without initial password.
func (s *Store) CreateSSOUser(username string, role Role, ssoSub, ssoUsername, ssoEmail string) (User, error) {
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

	saltBytes := make([]byte, 16)
	_, _ = rand.Read(saltBytes)
	saltHex := hex.EncodeToString(saltBytes)

	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	now := time.Now().UTC()
	u := User{
		ID:                 id,
		Username:           strings.TrimSpace(username),
		Role:               role,
		Active:             true,
		AuthSalt:           saltHex,
		AuthIterations:     600000,
		MustChangePassword: false,
		CreatedAt:          now,
		UpdatedAt:          now,
		SSOSub:             ssoSub,
		SSOUsername:        ssoUsername,
		SSOEmail:           ssoEmail,
		SSOLinkedAt:        now.Unix(),
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

// VerifyAuth checks the user's password or derived auth secret.
func (s *Store) VerifyAuth(username, secret string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byName[strings.ToLower(strings.TrimSpace(username))]
	if !exists {
		return User{}, ErrInvalidAuth
	}

	u := s.users[id]
	if !u.Active {
		return User{}, ErrUserInactive
	}
	if u.PasswordHash == "" {
		return User{}, ErrInvalidAuth
	}

	computed, err := HashPassword(secret, u.AuthSalt)
	if err != nil {
		return User{}, err
	}

	if subtle.ConstantTimeCompare([]byte(computed), []byte(u.PasswordHash)) != 1 {
		return User{}, ErrInvalidAuth
	}

	return u, nil
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

// UnlinkSSO removes an SSO identity from a user.
func (s *Store) UnlinkSSO(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	if u.SSOSub != "" {
		delete(s.bySSOSub, u.SSOSub)
	}

	u.SSOSub = ""
	u.SSOUsername = ""
	u.SSOEmail = ""
	u.SSOLinkedAt = 0
	u.UpdatedAt = time.Now().UTC()

	s.users[id] = u
	return s.saveLocked()
}

// SetPassword updates a user's password.
func (s *Store) SetPassword(id, newPassword string, requireChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	saltBytes := make([]byte, 16)
	_, _ = rand.Read(saltBytes)
	saltHex := hex.EncodeToString(saltBytes)

	hash, err := HashPassword(newPassword, saltHex)
	if err != nil {
		return err
	}

	u.PasswordHash = hash
	u.AuthSalt = saltHex
	u.MustChangePassword = requireChange
	u.UpdatedAt = time.Now().UTC()

	s.users[id] = u
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

// SetPaperRecovery saves the hashed paper recovery secret.
func (s *Store) SetPaperRecovery(id, recoverySecret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, exists := s.users[id]
	if !exists {
		return ErrNotFound
	}

	hash, err := HashPassword(recoverySecret, u.AuthSalt)
	if err != nil {
		return err
	}

	u.RecoveryHash = hash
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	return s.saveLocked()
}

// VerifyPaperRecovery checks if the paper recovery secret matches.
func (s *Store) VerifyPaperRecovery(username, recoverySecret string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.byName[strings.ToLower(strings.TrimSpace(username))]
	if !exists {
		return User{}, ErrInvalidAuth
	}

	u := s.users[id]
	if !u.Active {
		return User{}, ErrUserInactive
	}
	if u.RecoveryHash == "" {
		return User{}, errors.New("no recovery secret configured for account")
	}

	computed, err := HashPassword(recoverySecret, u.AuthSalt)
	if err != nil {
		return User{}, err
	}

	if subtle.ConstantTimeCompare([]byte(computed), []byte(u.RecoveryHash)) != 1 {
		return User{}, ErrInvalidAuth
	}

	return u, nil
}
