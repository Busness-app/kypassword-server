package devices

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
	ErrNotFound       = errors.New("device not found")
	ErrPairingExpired = errors.New("pairing PIN or challenge expired")
	ErrInvalidPIN     = errors.New("invalid pairing PIN")
)

// Device represents a registered client (mobile app or browser extension).
type Device struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	Name           string    `json:"name"`
	Platform       string    `json:"platform"`
	KeyFingerprint string    `json:"keyFingerprint,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
	LastIP         string    `json:"lastIp,omitempty"`
	Active         bool      `json:"active"`
}

// PairingSession holds an ephemeral 90-second pairing request.
type PairingSession struct {
	PIN       string    `json:"pin"` // 6 digits
	UserID    string    `json:"userId"`
	Secret    string    `json:"secret"` // Token for QR code
	ExpiresAt time.Time `json:"expiresAt"`
}

// Store manages registered devices and ephemeral pairing codes.
type Store struct {
	mu           sync.RWMutex
	filePath     string
	devices      map[string]Device         // DeviceID -> Device
	pairingPINs  map[string]PairingSession // PIN -> PairingSession
	pairingCodes map[string]PairingSession // Secret -> PairingSession
}

// NewStore loads or initializes the devices store.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir devices dir: %w", err)
	}

	filePath := filepath.Join(dir, "devices.json")
	s := &Store{
		filePath:     filePath,
		devices:      make(map[string]Device),
		pairingPINs:  make(map[string]PairingSession),
		pairingCodes: make(map[string]PairingSession),
	}

	data, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}

	var list []Device
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	for _, d := range list {
		s.devices[d.ID] = d
	}

	return s, nil
}

func (s *Store) saveLocked() error {
	list := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
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

// CreatePairingSession generates an ephemeral 90-second PIN and QR secret.
func (s *Store) CreatePairingSession(userID string) (PairingSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate 6-digit PIN
	pinBytes := make([]byte, 3)
	_, _ = rand.Read(pinBytes)
	pin := fmt.Sprintf("%06d", (int(pinBytes[0])<<16|int(pinBytes[1])<<8|int(pinBytes[2]))%1000000)

	secBytes := make([]byte, 24)
	_, _ = rand.Read(secBytes)
	secret := hex.EncodeToString(secBytes)

	session := PairingSession{
		PIN:       pin,
		UserID:    userID,
		Secret:    secret,
		ExpiresAt: time.Now().UTC().Add(90 * time.Second),
	}

	s.pairingPINs[pin] = session
	s.pairingCodes[secret] = session

	return session, nil
}

// RedeemPairing consumes a PIN or QR secret and registers the new device.
func (s *Store) RedeemPairing(codeOrPIN, deviceName, platform, ip string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var session PairingSession
	var ok bool

	trimmed := strings.TrimSpace(codeOrPIN)
	if len(trimmed) == 6 {
		session, ok = s.pairingPINs[trimmed]
	} else {
		session, ok = s.pairingCodes[trimmed]
	}

	if !ok || time.Now().UTC().After(session.ExpiresAt) {
		return Device{}, ErrPairingExpired
	}

	// Delete ephemeral session
	delete(s.pairingPINs, session.PIN)
	delete(s.pairingCodes, session.Secret)

	devBytes := make([]byte, 16)
	_, _ = rand.Read(devBytes)
	deviceID := hex.EncodeToString(devBytes)

	now := time.Now().UTC()
	device := Device{
		ID:         deviceID,
		UserID:     session.UserID,
		Name:       deviceName,
		Platform:   platform,
		CreatedAt:  now,
		LastSeenAt: now,
		LastIP:     ip,
		Active:     true,
	}

	s.devices[deviceID] = device
	if err := s.saveLocked(); err != nil {
		delete(s.devices, deviceID)
		return Device{}, err
	}

	return device, nil
}

// ListUserDevices returns all devices for a given user.
func (s *Store) ListUserDevices(userID string) []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []Device
	for _, d := range s.devices {
		if d.UserID == userID {
			result = append(result, d)
		}
	}
	return result
}

// Snapshot returns registered devices only. Pairing PINs are intentionally
// ephemeral and must not survive a restore.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
	}
	return json.MarshalIndent(list, "", "  ")
}

// Get finds a device by ID.
func (s *Store) Get(deviceID string) (Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, ok := s.devices[deviceID]
	if !ok {
		return Device{}, ErrNotFound
	}
	return d, nil
}

// Touch updates a device's last seen timestamp and IP.
func (s *Store) Touch(deviceID, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if d, ok := s.devices[deviceID]; ok {
		d.LastSeenAt = time.Now().UTC()
		d.LastIP = ip
		s.devices[deviceID] = d
		_ = s.saveLocked()
	}
}

// Revoke deactivates a device.
func (s *Store) Revoke(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.devices[deviceID]; !ok {
		return ErrNotFound
	}

	delete(s.devices, deviceID)
	return s.saveLocked()
}

// CancelUserPairings prevents an outstanding PIN from outliving deprovisioning.
func (s *Store) CancelUserPairings(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pin, pairing := range s.pairingPINs {
		if pairing.UserID == userID {
			delete(s.pairingPINs, pin)
			delete(s.pairingCodes, pairing.Secret)
		}
	}
}
