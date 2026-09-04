// Package backup owns KyPassword disaster-recovery collection, sealing, and deposits.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

const (
	ServiceName       = "kypassword"
	AppName           = "KyPassword"
	stateFile         = "kyrecovery.json"
	publicKeyFile     = "recovery.pub"
	tokenKeyFile      = "recovery-token.key"
	tokenAdditional   = ServiceName + ":kyrecovery_token"
	recoveryKeyLength = recoverykey.PublicKeyBytes
)

var (
	ErrNotPaired         = errors.New("backup: pair with KyRecovery first")
	ErrKeyPinMissing     = errors.New("backup: paired recovery public key is missing")
	ErrKeyMismatch       = errors.New("backup: recovery public key does not match its pin")
	ErrRemote            = errors.New("backup: KyRecovery")
	ErrReceiptUnrecorded = errors.New("backup: deposit succeeded but receipt was not recorded")
	ErrDepositInProgress = errors.New("backup: a deposit is already in progress")
	ErrInvalidURL        = errors.New("backup: invalid KyRecovery URL")
)

type RecoveryKey struct {
	Public      recoverykey.PublicKey
	Threshold   int
	TotalShares int
}

type Receipt struct {
	CapsuleID   string    `json:"capsule_id"`
	Digest      string    `json:"digest"`
	SizeBytes   int64     `json:"size_bytes"`
	DepositedAt time.Time `json:"deposited_at"`
}

type persistedState struct {
	RecoveryURL   string   `json:"recoveryUrl,omitempty"`
	SealedToken   string   `json:"sealedToken,omitempty"`
	RecoveryKeyID string   `json:"recoveryKeyId,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
	TotalShares   int      `json:"totalShares,omitempty"`
	LastDeposit   *Receipt `json:"lastDeposit,omitempty"`
}

type Status struct {
	Paired        bool     `json:"paired"`
	RecoveryURL   string   `json:"recoveryUrl,omitempty"`
	RecoveryKeyID string   `json:"recoveryKeyId,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
	TotalShares   int      `json:"totalShares,omitempty"`
	KeyHealthy    bool     `json:"keyHealthy"`
	LastDeposit   *Receipt `json:"lastDeposit,omitempty"`
}

type Pairing struct {
	URL   string
	Token string
	Key   RecoveryKey
}

type StateStore struct {
	mu  sync.Mutex
	dir string
}

func NewStateStore(configDir string) *StateStore { return &StateStore{dir: configDir} }

func (s *StateStore) statePath() string { return filepath.Join(s.dir, stateFile) }
func (s *StateStore) keyPath() string   { return filepath.Join(s.dir, publicKeyFile) }
func (s *StateStore) tokenPath() string { return filepath.Join(s.dir, tokenKeyFile) }

func (s *StateStore) loadLocked() (persistedState, error) {
	b, err := os.ReadFile(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return persistedState{}, nil
	}
	if err != nil {
		return persistedState{}, err
	}
	var state persistedState
	if err := json.Unmarshal(b, &state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func (s *StateStore) saveLocked(state persistedState) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath())
}

func validTopology(threshold, total int) bool {
	return threshold >= 2 && total >= threshold && total <= 255
}

// StorePairing pins the recovery key before persisting the deposit credential.
// A partial failure therefore cannot make a later, different key look like a first pairing.
func (s *StateStore) StorePairing(serverURL, token string, key RecoveryKey) error {
	if serverURL == "" || token == "" || key.Public.IsZero() || !validTopology(key.Threshold, key.TotalShares) {
		return errors.New("backup: incomplete pairing result")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.loadLocked()
	if err != nil {
		return err
	}
	if state.RecoveryKeyID != "" && state.RecoveryKeyID != key.Public.ID() {
		return fmt.Errorf("%w: already pinned to %s", fs.ErrExist, state.RecoveryKeyID)
	}
	if raw, err := keyfile.LoadEncoded(s.keyPath(), recoveryKeyLength, keyfile.Raw); err == nil {
		stored, parseErr := recoverykey.ParsePublicKey(raw)
		if parseErr != nil {
			return parseErr
		}
		if stored.ID() != key.Public.ID() {
			return fmt.Errorf("%w: recovery.pub contains %s", fs.ErrExist, stored.ID())
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := keyfile.Store(s.keyPath(), key.Public.Bytes(), keyfile.Raw); err != nil {
			return err
		}
	} else {
		return err
	}

	state.RecoveryKeyID = key.Public.ID()
	state.Threshold = key.Threshold
	state.TotalShares = key.TotalShares
	if err := s.saveLocked(state); err != nil {
		return err
	}
	sealed, err := s.sealTokenLocked(token)
	if err != nil {
		return err
	}
	state.RecoveryURL = serverURL
	state.SealedToken = sealed
	return s.saveLocked(state)
}

func (s *StateStore) sealTokenLocked(token string) (string, error) {
	key, err := keyfile.LoadOrCreate(s.tokenPath(), 32)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(token), []byte(tokenAdditional))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s *StateStore) openTokenLocked(encoded string) (string, error) {
	key, err := keyfile.Load(s.tokenPath(), 32)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	if len(raw) < aead.NonceSize() {
		return "", errors.New("backup: invalid sealed token")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(tokenAdditional))
	return string(plain), err
}

func (s *StateStore) loadRecoveryKeyLocked(state persistedState) (RecoveryKey, error) {
	if state.RecoveryKeyID == "" {
		return RecoveryKey{}, ErrNotPaired
	}
	raw, err := keyfile.LoadEncoded(s.keyPath(), recoveryKeyLength, keyfile.Raw)
	if errors.Is(err, os.ErrNotExist) {
		return RecoveryKey{}, ErrKeyPinMissing
	}
	if err != nil {
		return RecoveryKey{}, err
	}
	public, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return RecoveryKey{}, err
	}
	if public.ID() != state.RecoveryKeyID {
		return RecoveryKey{}, ErrKeyMismatch
	}
	if !validTopology(state.Threshold, state.TotalShares) {
		return RecoveryKey{}, errors.New("backup: invalid stored custodian topology")
	}
	return RecoveryKey{Public: public, Threshold: state.Threshold, TotalShares: state.TotalShares}, nil
}

func (s *StateStore) LoadPairing() (Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return Pairing{}, err
	}
	key, err := s.loadRecoveryKeyLocked(state)
	if err != nil {
		return Pairing{}, err
	}
	if state.RecoveryURL == "" || state.SealedToken == "" {
		return Pairing{}, ErrNotPaired
	}
	token, err := s.openTokenLocked(state.SealedToken)
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{URL: state.RecoveryURL, Token: token, Key: key}, nil
}

func (s *StateStore) RecoveryKey() (RecoveryKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return RecoveryKey{}, err
	}
	return s.loadRecoveryKeyLocked(state)
}

func (s *StateStore) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return Status{}, err
	}
	status := Status{Paired: state.RecoveryKeyID != "", RecoveryURL: state.RecoveryURL,
		RecoveryKeyID: state.RecoveryKeyID, Threshold: state.Threshold,
		TotalShares: state.TotalShares, LastDeposit: state.LastDeposit}
	if status.Paired {
		_, err = s.loadRecoveryKeyLocked(state)
		status.KeyHealthy = err == nil
	}
	return status, nil
}

func (s *StateStore) SaveReceipt(receipt Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return err
	}
	state.LastDeposit = &receipt
	return s.saveLocked(state)
}

func (s *StateStore) CapsuleFiles() ([]capsule.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	if state.RecoveryKeyID == "" {
		return nil, nil
	}
	var files []capsule.File
	for _, item := range []struct{ name string }{{stateFile}, {publicKeyFile}, {tokenKeyFile}} {
		b, err := os.ReadFile(filepath.Join(s.dir, item.name))
		if err != nil {
			return nil, fmt.Errorf("required backup member %s: %w", item.name, err)
		}
		files = append(files, capsule.File{Path: "config/" + item.name, Content: b, Mode: 0600})
	}
	return files, nil
}
