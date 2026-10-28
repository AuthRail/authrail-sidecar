//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func acquireStateLock(state string) (*os.File, error) {
	file, err := openStateLockFile(state)
	if err != nil {
		return nil, err
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{}); err != nil {
		file.Close()
		return nil, errors.New("deployment state is in use; stop its daemon before offline review")
	}
	return file, nil
}
