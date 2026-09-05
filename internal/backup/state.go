// Package backup owns KyPassword disaster-recovery collection, sealing, and deposits.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/keyfile"
	"github.com/Busness-app/ky-primitives/recoveryclient"
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
	ErrNotPaired         = recoveryclient.ErrNotPaired
	ErrKeyPinMissing     = recoveryclient.ErrKeyPinMissing
	ErrKeyMismatch       = recoveryclient.ErrKeyMismatch
	ErrRemote            = recoveryclient.ErrRemote
	ErrReceiptUnrecorded = recoveryclient.ErrReceiptUnrecorded
	ErrDepositInProgress = recoveryclient.ErrInProgress
	ErrInvalidURL        = errors.New("backup: invalid KyRecovery URL")
)

type RecoveryKey = recoveryclient.RecoveryKey
type Receipt = recoveryclient.Receipt

type persistedState struct {
	RecoveryURL   *string     `json:"recoveryUrl,omitempty"`
	SealedToken   *string     `json:"sealedToken,omitempty"`
	RecoveryKeyID *string     `json:"recoveryKeyId,omitempty"`
	Threshold     *int        `json:"threshold,omitempty"`
	TotalShares   *int        `json:"totalShares,omitempty"`
	LastDeposit   *Receipt    `json:"lastDeposit,omitempty"`
	Interval      *string     `json:"intervalSec,omitempty"`
	LastAttempt   *string     `json:"lastAttempt,omitempty"`
	LastRun       *RunSummary `json:"lastRun,omitempty"`
}

type Status struct {
	Paired        bool     `json:"paired"`
	RecoveryURL   string   `json:"recoveryUrl,omitempty"`
	RecoveryKeyID string   `json:"recoveryKeyId,omitempty"`
	Threshold     int      `json:"threshold,omitempty"`
	TotalShares   int      `json:"totalShares,omitempty"`
	KeyHealthy    bool     `json:"keyHealthy"`
	Error         string   `json:"error,omitempty"`
	LastDeposit   *Receipt `json:"lastDeposit,omitempty"`
}

type Pairing = recoveryclient.Pairing

type StateStore struct {
	mu          sync.Mutex
	operationMu sync.Mutex
	dir         string
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
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return persistedState{}, errors.New("invalid backup settings object")
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

// lockedSettings is used while StateStore.mu holds the complete lifecycle operation.
type lockedSettings struct{ s *StateStore }

func (a lockedSettings) Get(key string) (string, error) {
	st, err := a.s.loadLocked()
	if err != nil {
		return "", err
	}
	switch key {
	case "kyrecovery_url":
		if st.RecoveryURL != nil {
			return *st.RecoveryURL, nil
		}
	case "kyrecovery_token_enc":
		if st.SealedToken != nil {
			return *st.SealedToken, nil
		}
	case "kyrecovery_key_id":
		if st.RecoveryKeyID != nil {
			return *st.RecoveryKeyID, nil
		}
	case "kyrecovery_threshold":
		if st.Threshold != nil {
			return strconv.Itoa(*st.Threshold), nil
		}
	case "kyrecovery_total_shares":
		if st.TotalShares != nil {
			return strconv.Itoa(*st.TotalShares), nil
		}
	case "kyrecovery_last_deposit":
		if st.LastDeposit != nil {
			b, e := json.Marshal(st.LastDeposit)
			return string(b), e
		}
	case "backup_interval_sec":
		if st.Interval != nil {
			return *st.Interval, nil
		}
	case "backup_last_attempt":
		if st.LastAttempt != nil {
			return *st.LastAttempt, nil
		}
	default:
		return "", fmt.Errorf("unknown backup setting %q", key)
	}
	return "", recoveryclient.ErrNotFound
}
func (a lockedSettings) Set(key, value string) error { return a.write(key, &value) }
func (a lockedSettings) Delete(key string) error     { return a.write(key, nil) }
func (a lockedSettings) write(key string, value *string) error {
	st, err := a.s.loadLocked()
	if err != nil {
		return err
	}
	v := ""
	if value != nil {
		v = *value
	}
	switch key {
	case "kyrecovery_url":
		st.RecoveryURL = value
	case "kyrecovery_token_enc":
		st.SealedToken = value
	case "kyrecovery_key_id":
		st.RecoveryKeyID = value
	case "kyrecovery_threshold":
		st.Threshold = nil
		if value != nil {
			var n int
			n, err = strconv.Atoi(v)
			st.Threshold = &n
		}
	case "kyrecovery_total_shares":
		st.TotalShares = nil
		if value != nil {
			var n int
			n, err = strconv.Atoi(v)
			st.TotalShares = &n
		}
	case "kyrecovery_last_deposit":
		st.LastDeposit = nil
		if value != nil {
			err = json.Unmarshal([]byte(v), &st.LastDeposit)
		}
	case "backup_interval_sec":
		st.Interval = value
	case "backup_last_attempt":
		st.LastAttempt = value
	default:
		return fmt.Errorf("unknown backup setting %q", key)
	}
	if err != nil {
		return err
	}
	return a.s.saveLocked(st)
}
func (s *StateStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return (lockedSettings{s}).Get(key)
}
func (s *StateStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return (lockedSettings{s}).Set(key, value)
}
func (s *StateStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return (lockedSettings{s}).Delete(key)
}

type tokenSealer struct{ s *StateStore }

func (a tokenSealer) Seal(p []byte) (string, error) { return a.s.sealTokenLocked(string(p)) }
func (a tokenSealer) Open(v string) ([]byte, error) {
	p, e := a.s.openTokenLocked(v)
	return []byte(p), e
}

func (s *StateStore) StorePairing(url, token string, key RecoveryKey) error {
	if !s.operationMu.TryLock() {
		return ErrDepositInProgress
	}
	defer s.operationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	settings := lockedSettings{s}
	if err := recoveryclient.StoreRecoveryKey(s.dir, settings, key); err != nil {
		return err
	}
	return recoveryclient.StorePairing(settings, tokenSealer{s}, url, token)
}
func (s *StateStore) Pin(key RecoveryKey) error {
	if !s.operationMu.TryLock() {
		return ErrDepositInProgress
	}
	defer s.operationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return recoveryclient.StoreRecoveryKey(s.dir, lockedSettings{s}, key)
}
func (s *StateStore) Unpair() error {
	if !s.operationMu.TryLock() {
		return ErrDepositInProgress
	}
	defer s.operationMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return recoveryclient.ClearPairing(lockedSettings{s})
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

func (s *StateStore) recoveryKeyLocked() (RecoveryKey, error) {
	key, err := recoveryclient.LoadRecoveryKey(s.dir, lockedSettings{s})
	if errors.Is(err, ErrNotPaired) {
		if _, pinErr := (lockedSettings{s}).Get("kyrecovery_key_id"); pinErr == nil {
			return key, ErrKeyPinMissing
		}
	}
	return key, err
}
func (s *StateStore) RecoveryKey() (RecoveryKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recoveryKeyLocked()
}
func (s *StateStore) LoadPairing() (Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.recoveryKeyLocked(); err != nil {
		return Pairing{}, err
	}
	return recoveryclient.LoadPairing(s.dir, lockedSettings{s}, tokenSealer{s})
}
func (s *StateStore) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.loadLocked()
	if err != nil {
		return Status{}, err
	}
	status := Status{Paired: valueOf(st.RecoveryURL) != "" && valueOf(st.SealedToken) != "", RecoveryURL: valueOf(st.RecoveryURL),
		RecoveryKeyID: valueOf(st.RecoveryKeyID), Threshold: valueOf(st.Threshold), TotalShares: valueOf(st.TotalShares), LastDeposit: st.LastDeposit}
	if valueOf(st.RecoveryKeyID) != "" {
		_, err = s.recoveryKeyLocked()
		status.KeyHealthy = err == nil
		if err != nil {
			status.Error = "recovery public key is missing or mismatched"
		}
	}
	if valueOf(st.RecoveryURL) != "" || valueOf(st.SealedToken) != "" {
		if _, err := recoveryclient.LoadPairing(s.dir, lockedSettings{s}, tokenSealer{s}); err != nil {
			status.Error = "recovery pairing is incomplete or cannot be opened"
		}
	}
	return status, nil
}
func (s *StateStore) SaveReceipt(receipt Receipt) error {
	b, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return s.Set("kyrecovery_last_deposit", string(b))
}

func (s *StateStore) CapsuleFiles() ([]capsule.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	if valueOf(state.RecoveryKeyID) == "" {
		return nil, nil
	}
	var files []capsule.File
	names := []string{stateFile, publicKeyFile}
	if valueOf(state.SealedToken) != "" {
		names = append(names, tokenKeyFile)
	} else if _, err := os.Stat(s.tokenPath()); err == nil {
		names = append(names, tokenKeyFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, name := range names {
		item := struct{ name string }{name}
		b, err := os.ReadFile(filepath.Join(s.dir, item.name))
		if err != nil {
			return nil, fmt.Errorf("required backup member %s: %w", item.name, err)
		}
		files = append(files, capsule.File{Path: "config/" + item.name, Content: b, Mode: 0600})
	}
	return files, nil
}

// Presence matters to Settings: an explicit empty value is not a missing field.
func valueOf[T any](p *T) (zero T) {
	if p != nil {
		return *p
	}
	return zero
}
