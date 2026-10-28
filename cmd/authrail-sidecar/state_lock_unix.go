//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func acquireStateLock(state string) (*os.File, error) {
	file, err := openStateLockFile(state)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("deployment state is in use; stop its daemon before offline review")
	}
	return file, nil
}
