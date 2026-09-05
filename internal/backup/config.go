package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

func ConfigFromEnv() (Config, error) {
	c := Config{Directory: os.Getenv("KYPASSWORD_BACKUP_DIR"), Keep: 7, Interval: 24 * time.Hour}
	if c.Directory != "" && !filepath.IsAbs(c.Directory) {
		return c, fmt.Errorf("KYPASSWORD_BACKUP_DIR must be absolute")
	}
	if c.Directory != "" {
		data := os.Getenv("DATA_DIR")
		if data == "" {
			data = "./data"
		}
		config := os.Getenv("CONFIG_DIR")
		if config == "" {
			config = "./config"
		}
		dir, err := resolvedPath(c.Directory)
		if err != nil {
			return c, fmt.Errorf("KYPASSWORD_BACKUP_DIR: %w", err)
		}
		for _, root := range []string{config, filepath.Join(data, "vaults"), filepath.Join(data, "audit"), filepath.Join(data, "drill")} {
			root, err = resolvedPath(root)
			if err != nil {
				return c, fmt.Errorf("KYPASSWORD_BACKUP_DIR: %w", err)
			}
			if containsPath(root, dir) || containsPath(dir, root) {
				return c, fmt.Errorf("KYPASSWORD_BACKUP_DIR overlaps protected directory %s", root)
			}
		}
		c.Directory = dir
	}
	if v := os.Getenv("KYPASSWORD_BACKUP_KEEP"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 {
			return c, fmt.Errorf("KYPASSWORD_BACKUP_KEEP must be at least 1")
		}
		c.Keep = n
	}
	if v := os.Getenv("KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY"); v != "" {
		b, e := strconv.ParseBool(v)
		if e != nil {
			return c, fmt.Errorf("KYPASSWORD_BACKUP_ALLOW_PRIVATE_RECOVERY must be a boolean")
		}
		c.AllowPrivate = b
	}
	if v := os.Getenv("KYPASSWORD_BACKUP_DEPOSIT_INTERVAL"); v != "" {
		d, e := time.ParseDuration(v)
		if e != nil {
			return c, fmt.Errorf("KYPASSWORD_BACKUP_DEPOSIT_INTERVAL: %w", e)
		}
		c.Interval = d
	}
	if c.Interval != 0 && (c.Interval < recoveryclient.MinInterval || c.Interval > recoveryclient.MaxInterval || c.Interval%time.Second != 0) {
		return c, fmt.Errorf("KYPASSWORD_BACKUP_DEPOSIT_INTERVAL must be 0 or whole seconds between 15m and 8784h")
	}
	return c, nil
}

type FullStatus struct {
	Status
	BackupDir    string                     `json:"backupDir"`
	AllowPrivate bool                       `json:"allowPrivate"`
	LocalCopies  []recoveryclient.LocalCopy `json:"localCopies"`
	IntervalSec  int64                      `json:"intervalSec"`
	NextAttempt  *time.Time                 `json:"nextAttempt,omitempty"`
	LastAttempt  *string                    `json:"lastAttempt,omitempty"`
	LastRun      *RunSummary                `json:"lastRun,omitempty"`
}

func (s *Service) Status() (FullStatus, error) {
	base, err := s.State.Status()
	if err != nil {
		return FullStatus{}, err
	}
	out := FullStatus{Status: base, BackupDir: s.Config.Directory, AllowPrivate: s.Config.AllowPrivate, LocalCopies: []recoveryclient.LocalCopy{}}
	interval, err := recoveryclient.Interval(s.Config.Interval, s.State)
	if err != nil {
		return out, err
	}
	out.IntervalSec = int64(interval / time.Second)
	next, ok, err := recoveryclient.NextRun(s.Config.Interval, s.State)
	if err != nil {
		return out, err
	}
	if ok {
		out.NextAttempt = &next
	}
	if s.Config.Directory != "" {
		out.LocalCopies, err = recoveryclient.ListLocalCopies(s.Config.Directory, ServiceName)
		if err != nil {
			return out, err
		}
	}
	s.State.mu.Lock()
	defer s.State.mu.Unlock()
	st, err := s.State.loadLocked()
	out.LastAttempt = st.LastAttempt
	out.LastRun = st.LastRun
	return out, err
}

// Resolve existing ancestors too: the backup directory may not exist until the first run.
func resolvedPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent, err := resolvedPath(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}
func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
