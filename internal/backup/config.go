package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

func ConfigFromEnv() (Config, error) {
	c := Config{Directory: os.Getenv("KYPASSWORD_BACKUP_DIR"), Keep: 7, Interval: 24 * time.Hour}
	if c.Directory != "" && !filepath.IsAbs(c.Directory) {
		return c, fmt.Errorf("KYPASSWORD_BACKUP_DIR must be absolute")
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
