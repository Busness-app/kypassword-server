package main

import (
	"testing"
	"time"
)

func TestBackupDepositInterval(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		bad   bool
	}{
		{"", 24 * time.Hour, false},
		{"0", 0, false},
		{"15m", 15 * time.Minute, false},
		{"1h", time.Hour, false},
		{"14m59s", 0, true},
		{"-1h", 0, true},
		{"tomorrow", 0, true},
	}
	for _, test := range tests {
		got, err := backupDepositInterval(test.value)
		if (err != nil) != test.bad || got != test.want {
			t.Errorf("backupDepositInterval(%q) = %s, %v", test.value, got, err)
		}
	}
}

func TestInstanceLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireInstanceLock(dir); err == nil {
		second.Close()
		t.Fatal("second instance lock succeeded")
	}
}
