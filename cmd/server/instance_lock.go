package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type instanceLock struct{ file *os.File }

func acquireInstanceLock(configDir string) (*instanceLock, error) {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(configDir, ".kypassword.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another KyPassword process is using %s", configDir)
	}
	return &instanceLock{file: file}, nil
}

func (l *instanceLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
