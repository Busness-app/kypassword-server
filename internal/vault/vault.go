package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("vault not found")
	ErrConflict = errors.New("vault version conflict: a newer version exists on the server")
)

// ConflictError conveys details about a rejected upload.
type ConflictError struct {
	CurrentVersion  int64  `json:"currentVersion"`
	ExpectedVersion int64  `json:"expectedVersion"`
	ConflictID      string `json:"conflictId"`
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("vault conflict: current version is %d, expected %d (saved as conflict %s)",
		e.CurrentVersion, e.ExpectedVersion, e.ConflictID)
}

// DeviceEnvelope holds the device-wrapped vault key.
type DeviceEnvelope struct {
	DeviceID  string    `json:"deviceId"`
	Name      string    `json:"name"`
	Envelope  string    `json:"envelope"` // Base64 encrypted key envelope
	CreatedAt time.Time `json:"createdAt"`
}

// Metadata holds server-side zero-knowledge envelopes and versioning state.
type Metadata struct {
	UserID           string                    `json:"userId"`
	Version          int64                     `json:"version"`
	Checksum         string                    `json:"checksum"` // SHA-256 of vault.kdbx
	SizeBytes        int64                     `json:"sizeBytes"`
	UpdatedAt        time.Time                 `json:"updatedAt"`
	UpdatedByDevice  string                    `json:"updatedByDevice,omitempty"`
	PasswordEnvelope string                    `json:"passwordEnvelope,omitempty"`
	RecoveryEnvelope string                    `json:"recoveryEnvelope,omitempty"`
	DeviceEnvelopes  map[string]DeviceEnvelope `json:"deviceEnvelopes,omitempty"`
}

// HistoryEntry represents a past vault snapshot.
type HistoryEntry struct {
	ID        string    `json:"id"`
	Version   int64     `json:"version"`
	SizeBytes int64     `json:"sizeBytes"`
	Checksum  string    `json:"checksum"`
	Timestamp time.Time `json:"timestamp"`
}

// ConflictEntry represents a preserved rejected save.
type ConflictEntry struct {
	ID              string    `json:"id"`
	ExpectedVersion int64     `json:"expectedVersion"`
	DeviceID        string    `json:"deviceId"`
	SizeBytes       int64     `json:"sizeBytes"`
	Timestamp       time.Time `json:"timestamp"`
}

// Store manages user vaults, history snapshots, and conflict files.
type Store struct {
	mu            sync.RWMutex
	baseDir       string
	retentionDays int
}

// NewStore initializes the vault manager.
func NewStore(baseDir string, retentionDays int) (*Store, error) {
	if retentionDays <= 0 {
		retentionDays = 90
	}
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir vault base dir: %w", err)
	}
	return &Store{
		baseDir:       baseDir,
		retentionDays: retentionDays,
	}, nil
}

func (s *Store) userVaultDir(userID string) string {
	return filepath.Join(s.baseDir, userID)
}

func (s *Store) metaPath(userID string) string {
	return filepath.Join(s.userVaultDir(userID), "metadata.json")
}

func (s *Store) kdbxPath(userID string) string {
	return filepath.Join(s.userVaultDir(userID), "vault.kdbx")
}

func (s *Store) historyDir(userID string) string {
	return filepath.Join(s.userVaultDir(userID), "history")
}

func (s *Store) conflictsDir(userID string) string {
	return filepath.Join(s.userVaultDir(userID), "conflicts")
}

// GetMetadata returns the vault metadata and envelopes for a user.
func (s *Store) GetMetadata(userID string) (Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.metaPath(userID))
	if os.IsNotExist(err) {
		return Metadata{
			UserID:          userID,
			Version:         0,
			DeviceEnvelopes: make(map[string]DeviceEnvelope),
		}, nil
	}
	if err != nil {
		return Metadata{}, err
	}

	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return Metadata{}, err
	}
	if meta.DeviceEnvelopes == nil {
		meta.DeviceEnvelopes = make(map[string]DeviceEnvelope)
	}
	return meta, nil
}

// OpenVault returns a reader for the raw encrypted KDBX file and its current ETag/version.
func (s *Store) OpenVault(userID string) (io.ReadCloser, Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	meta, err := s.GetMetadata(userID)
	if err != nil {
		return nil, Metadata{}, err
	}
	if meta.Version == 0 {
		return nil, Metadata{}, ErrNotFound
	}

	f, err := os.Open(s.kdbxPath(userID))
	if err != nil {
		return nil, Metadata{}, err
	}
	return f, meta, nil
}

// SaveEnvelopes updates the key envelopes without modifying the KDBX file.
func (s *Store) SaveEnvelopes(userID string, passwordEnvelope, recoveryEnvelope string, deviceEnvelopes map[string]DeviceEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vDir := s.userVaultDir(userID)
	if err := os.MkdirAll(vDir, 0700); err != nil {
		return err
	}

	meta, _ := s.getMetadataLocked(userID)
	if passwordEnvelope != "" {
		meta.PasswordEnvelope = passwordEnvelope
	}
	if recoveryEnvelope != "" {
		meta.RecoveryEnvelope = recoveryEnvelope
	}
	if deviceEnvelopes != nil {
		meta.DeviceEnvelopes = deviceEnvelopes
	}
	meta.UpdatedAt = time.Now().UTC()

	return s.saveMetadataLocked(userID, meta)
}

// SetDeviceEnvelope adds or updates a single device's wrapped key envelope.
func (s *Store) SetDeviceEnvelope(userID string, env DeviceEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	vDir := s.userVaultDir(userID)
	if err := os.MkdirAll(vDir, 0700); err != nil {
		return err
	}

	meta, _ := s.getMetadataLocked(userID)
	if meta.DeviceEnvelopes == nil {
		meta.DeviceEnvelopes = make(map[string]DeviceEnvelope)
	}
	meta.DeviceEnvelopes[env.DeviceID] = env
	meta.UpdatedAt = time.Now().UTC()

	return s.saveMetadataLocked(userID, meta)
}

// RemoveDeviceEnvelope revokes a device key envelope.
func (s *Store) RemoveDeviceEnvelope(userID, deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, err := s.getMetadataLocked(userID)
	if err != nil {
		return err
	}

	delete(meta.DeviceEnvelopes, deviceID)
	meta.UpdatedAt = time.Now().UTC()

	return s.saveMetadataLocked(userID, meta)
}

func (s *Store) getMetadataLocked(userID string) (Metadata, error) {
	data, err := os.ReadFile(s.metaPath(userID))
	if os.IsNotExist(err) {
		return Metadata{
			UserID:          userID,
			Version:         0,
			DeviceEnvelopes: make(map[string]DeviceEnvelope),
		}, nil
	}
	if err != nil {
		return Metadata{}, err
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return Metadata{}, err
	}
	if meta.DeviceEnvelopes == nil {
		meta.DeviceEnvelopes = make(map[string]DeviceEnvelope)
	}
	return meta, nil
}

func (s *Store) saveMetadataLocked(userID string, meta Metadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.metaPath(userID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.metaPath(userID))
}

// SaveVault saves a new encrypted KDBX version atomically.
func (s *Store) SaveVault(userID string, expectedVersion int64, kdbxData []byte, passwordEnvelope, recoveryEnvelope string, deviceID string) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	vDir := s.userVaultDir(userID)
	if err := os.MkdirAll(vDir, 0700); err != nil {
		return Metadata{}, err
	}
	if err := os.MkdirAll(s.historyDir(userID), 0700); err != nil {
		return Metadata{}, err
	}
	if err := os.MkdirAll(s.conflictsDir(userID), 0700); err != nil {
		return Metadata{}, err
	}

	current, _ := s.getMetadataLocked(userID)

	// Optimistic concurrency check
	if expectedVersion != current.Version {
		// Conflict! Preserve rejected upload into conflicts directory
		conflictID := fmt.Sprintf("%d_%s_exp%d", time.Now().UTC().UnixNano(), deviceID, expectedVersion)
		conflictFile := filepath.Join(s.conflictsDir(userID), conflictID+".kdbx")
		_ = os.WriteFile(conflictFile, kdbxData, 0600)

		return Metadata{}, &ConflictError{
			CurrentVersion:  current.Version,
			ExpectedVersion: expectedVersion,
			ConflictID:      conflictID,
		}
	}

	// Archive current version to history (if it exists)
	if current.Version > 0 {
		historyID := fmt.Sprintf("%d_v%d", current.UpdatedAt.Unix(), current.Version)
		currentKdbx, err := os.ReadFile(s.kdbxPath(userID))
		if err == nil {
			_ = os.WriteFile(filepath.Join(s.historyDir(userID), historyID+".kdbx"), currentKdbx, 0600)
		}
	}

	// Compute checksum
	h := sha256.Sum256(kdbxData)
	checksumHex := hex.EncodeToString(h[:])

	// Write new KDBX file
	tmpKdbx := s.kdbxPath(userID) + ".tmp"
	if err := os.WriteFile(tmpKdbx, kdbxData, 0600); err != nil {
		return Metadata{}, err
	}
	if err := os.Rename(tmpKdbx, s.kdbxPath(userID)); err != nil {
		return Metadata{}, err
	}

	// Update metadata
	now := time.Now().UTC()
	newVersion := current.Version + 1
	nextMeta := Metadata{
		UserID:           userID,
		Version:          newVersion,
		Checksum:         checksumHex,
		SizeBytes:        int64(len(kdbxData)),
		UpdatedAt:        now,
		UpdatedByDevice:  deviceID,
		PasswordEnvelope: current.PasswordEnvelope,
		RecoveryEnvelope: current.RecoveryEnvelope,
		DeviceEnvelopes:  current.DeviceEnvelopes,
	}

	if passwordEnvelope != "" {
		nextMeta.PasswordEnvelope = passwordEnvelope
	}
	if recoveryEnvelope != "" {
		nextMeta.RecoveryEnvelope = recoveryEnvelope
	}

	if err := s.saveMetadataLocked(userID, nextMeta); err != nil {
		return Metadata{}, err
	}

	// Trigger async retention pruning
	go s.pruneOldHistory(userID)

	return nextMeta, nil
}

// ListHistory returns all preserved historical versions.
func (s *Store) ListHistory(userID string) ([]HistoryEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]HistoryEntry, 0)
	files, err := os.ReadDir(s.historyDir(userID))
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".kdbx") {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}

		id := strings.TrimSuffix(f.Name(), ".kdbx")
		// id format: {unixTimestamp}_v{version}
		var version int64 = 0
		if idx := strings.Index(id, "_v"); idx != -1 {
			v, _ := strconv.ParseInt(id[idx+2:], 10, 64)
			version = v
		}

		entries = append(entries, HistoryEntry{
			ID:        id,
			Version:   version,
			SizeBytes: info.Size(),
			Timestamp: info.ModTime().UTC(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// RestoreHistory rolls back the active vault to a past snapshot.
func (s *Store) RestoreHistory(userID, historyID string) (Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	histFile := filepath.Join(s.historyDir(userID), historyID+".kdbx")
	histData, err := os.ReadFile(histFile)
	if err != nil {
		return Metadata{}, fmt.Errorf("read history file: %w", err)
	}

	current, _ := s.getMetadataLocked(userID)

	// Archive current to history
	if current.Version > 0 {
		currHistID := fmt.Sprintf("%d_v%d_before_rollback", current.UpdatedAt.Unix(), current.Version)
		currKdbx, err := os.ReadFile(s.kdbxPath(userID))
		if err == nil {
			_ = os.WriteFile(filepath.Join(s.historyDir(userID), currHistID+".kdbx"), currKdbx, 0600)
		}
	}

	// Write restored KDBX
	tmpKdbx := s.kdbxPath(userID) + ".tmp"
	if err := os.WriteFile(tmpKdbx, histData, 0600); err != nil {
		return Metadata{}, err
	}
	if err := os.Rename(tmpKdbx, s.kdbxPath(userID)); err != nil {
		return Metadata{}, err
	}

	h := sha256.Sum256(histData)
	checksumHex := hex.EncodeToString(h[:])

	now := time.Now().UTC()
	nextMeta := Metadata{
		UserID:           userID,
		Version:          current.Version + 1,
		Checksum:         checksumHex,
		SizeBytes:        int64(len(histData)),
		UpdatedAt:        now,
		UpdatedByDevice:  "rollback",
		PasswordEnvelope: current.PasswordEnvelope,
		RecoveryEnvelope: current.RecoveryEnvelope,
		DeviceEnvelopes:  current.DeviceEnvelopes,
	}

	if err := s.saveMetadataLocked(userID, nextMeta); err != nil {
		return Metadata{}, err
	}

	return nextMeta, nil
}

// ListConflicts returns all un-resolved conflict uploads.
func (s *Store) ListConflicts(userID string) ([]ConflictEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]ConflictEntry, 0)
	files, err := os.ReadDir(s.conflictsDir(userID))
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".kdbx") {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}

		id := strings.TrimSuffix(f.Name(), ".kdbx")
		entries = append(entries, ConflictEntry{
			ID:        id,
			SizeBytes: info.Size(),
			Timestamp: info.ModTime().UTC(),
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})

	return entries, nil
}

// DiscardConflict removes a conflict file.
func (s *Store) DiscardConflict(userID, conflictID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conflictFile := filepath.Join(s.conflictsDir(userID), conflictID+".kdbx")
	return os.Remove(conflictFile)
}

func (s *Store) pruneOldHistory(userID string) {
	cutoff := time.Now().AddDate(0, 0, -s.retentionDays)
	hDir := s.historyDir(userID)

	files, err := os.ReadDir(hDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if info, err := f.Info(); err == nil {
			if info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(hDir, f.Name()))
			}
		}
	}
}
