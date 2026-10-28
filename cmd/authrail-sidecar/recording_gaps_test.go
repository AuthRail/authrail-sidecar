package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRecordingGapOperatorCannotRaceDaemonStateLock(t *testing.T) {
	state := filepath.Join(t.TempDir(), "private", "state.json")
	lock, err := acquireStateLock(state)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"list", "--state-file", state, "--organisation-id", "00000000-0000-4000-8000-000000000001", "--deployment-id", "00000000-0000-4000-8000-000000000002"}
	var output bytes.Buffer
	if err := runRecordingGaps(args, &output); err == nil {
		t.Fatal("offline review raced an active daemon lock")
	}
	if output.Len() != 0 {
		t.Fatal("blocked command exposed report state")
	}
	lock.Close()
	if err := runRecordingGaps(args, &output); err != nil {
		t.Fatalf("released process lock did not permit offline review: %v", err)
	}
}
