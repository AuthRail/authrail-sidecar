//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package main

import (
	"errors"
	"os"
)

func acquireStateLock(string) (*os.File, error) {
	return nil, errors.New("exclusive deployment state locking is unsupported on this platform")
}
