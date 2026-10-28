package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"

	"github.com/AuthRail/authrail-sidecar/sidecar"
)

// Host operators run this offline after stopping the exact deployment daemon.
// Acknowledgement retains a private signed-report archive, not an AuthRail
// execution receipt or authorization decision. Legacy daemons predate the lock.
func runRecordingGaps(args []string, output io.Writer) error {
	if len(args) == 0 || (args[0] != "list" && args[0] != "acknowledge") {
		return errors.New("usage: recording-gaps list|acknowledge --state-file ABSOLUTE_PATH --organisation-id UUID --deployment-id UUID [--fingerprint SHA256 --reviewer ID --reason REVIEW]")
	}
	flags := flag.NewFlagSet("recording-gaps "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	state := flags.String("state-file", "", "exact absolute deployment state path")
	org := flags.String("organisation-id", "", "exact organisation ID")
	deployment := flags.String("deployment-id", "", "exact deployment ID")
	fingerprint := flags.String("fingerprint", "", "complete signed receipt fingerprint from list")
	reviewer := flags.String("reviewer", "", "operator identity retained in local audit archive")
	reason := flags.String("reason", "", "review explanation retained in local audit archive")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("recording gap arguments are invalid")
	}
	if !filepath.IsAbs(*state) || *org == "" || *deployment == "" {
		return errors.New("exact absolute state path and deployment identity are required")
	}
	lock, err := acquireStateLock(*state)
	if err != nil {
		return err
	}
	defer lock.Close()
	review, err := sidecar.OpenExecutionGapReview(*state, *org, *deployment)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if args[0] == "acknowledge" {
		ack, err := review.Acknowledge(*fingerprint, *reviewer, *reason)
		if err != nil {
			return err
		}
		return encoder.Encode(ack)
	}
	pending, acknowledged, err := review.List()
	if err != nil {
		return err
	}
	return encoder.Encode(struct {
		Pending      []sidecar.ExecutionGap                `json:"pending"`
		Acknowledged []sidecar.ExecutionGapAcknowledgement `json:"acknowledged"`
	}{pending, acknowledged})
}

func openStateLockFile(state string) (*os.File, error) {
	if state == "" {
		return nil, errors.New("state path is required for process lock")
	}
	dir := filepath.Dir(state)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("state lock directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state lock directory must be private")
	}
	path := state + ".lock"
	existing, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("state lock is unavailable")
	}
	if err == nil && (!existing.Mode().IsRegular() || existing.Mode().Perm()&0077 != 0) {
		return nil, errors.New("state lock must be a private regular file")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("state lock cannot be opened")
	}
	opened, err := file.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || currentErr != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 || !os.SameFile(opened, current) {
		file.Close()
		return nil, errors.New("state lock changed or is unsafe")
	}
	return file, nil
}
