package setup

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// These small bindings use the released SDKs. They neither evaluate rules nor
// infer a caller, resource, complete history or permission from agent text.
//
//go:embed bindings/*
var sdkBindings embed.FS

func saveBindings(directory string, value connection, output io.Writer) error {
	root, err := privateRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.MarshalIndent(struct {
		FormatVersion  int          `json:"formatVersion"`
		OrganisationID string       `json:"organisationId"`
		DeploymentID   string       `json:"deploymentId"`
		Integration    *integration `json:"integration"`
	}{1, value.OrganisationID, value.DeploymentID, value.Integration}, "", "  ")
	if err != nil {
		return errors.New("cannot prepare SDK action bindings")
	}
	// A refreshed selection replaces only this non-secret guidance snapshot.
	// Keys, recovery journals, native state and copied application code are untouched.
	if info, err := root.Lstat("integration.json"); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("integration.json must be a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staged := ".integration-" + randomValue()
	if err := createPrivate(root, staged, append(data, '\n')); err != nil {
		return err
	}
	defer root.Remove(staged)
	if err := root.Rename(staged, "integration.json"); err != nil {
		return errors.New("cannot save SDK action bindings")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return err
	}
	for _, name := range []string{"authrail_binding_v1.mjs", "authrail_binding_v1.py", "authrail_binding_v1.go"} {
		sourceName := name
		if name == "authrail_binding_v1.go" {
			sourceName += ".txt"
		}
		content, err := sdkBindings.ReadFile("bindings/" + sourceName)
		if err != nil {
			return errors.New("SDK bindings are missing from this executable")
		}
		previous, err := readPrivate(root, name)
		if errors.Is(err, os.ErrNotExist) {
			if err := createPrivate(root, name, content); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("cannot safely read %s; no binding was replaced", name)
		} else if !bytes.Equal(previous, content) {
			// Keep application edits and older generated code. A deterministic sibling
			// lets the developer review an update without breaking the installation.
			replacement := fmt.Sprintf("%s.%x.generated", name, sha256.Sum256(content))
			existing, err := readPrivate(root, replacement)
			if errors.Is(err, os.ErrNotExist) {
				if err := createPrivate(root, replacement, content); err != nil {
					return err
				}
			} else if err != nil || !bytes.Equal(existing, content) {
				return fmt.Errorf("cannot safely save %s; no binding was replaced", name)
			}
			fmt.Fprintf(output, "Preserved %s. Review the supplied binding in %s before changing your application.\n", name, replacement)
		}
	}
	fmt.Fprintln(output, "Node, Go and Python SDK bindings saved beside integration.json. They read private connection files at runtime.")
	fmt.Fprintln(output, "Choose your application's language and install only its SDK:")
	fmt.Fprintln(output, "  Node.js: npm install @authrail/sdk-node@0.1.1")
	fmt.Fprintln(output, "  Go: go get github.com/AuthRail/authrail-sdk-go@v0.1.1")
	fmt.Fprintln(output, "  Python: python -m pip install authrail==0.1.1")
	if value.Integration == nil || len(value.Integration.Operations) == 0 {
		fmt.Fprintln(output, "Action details are unavailable. A manager with Rails access can check the deployment's selected published Rails. Rerun setup after selecting Rails or updating your access; keys and tokens are retained.")
	} else {
		fmt.Fprintf(output, "Selected actions (%s, configuration sequence %d):\n", value.Integration.Mode, value.Integration.Sequence)
		for _, operation := range value.Integration.Operations {
			// Reviewed labels are untrusted terminal text. Quote control characters.
			fmt.Fprintf(output, "  %s  %q\n", operation.VersionID, operation.Summary)
		}
		fmt.Fprintln(output, "Bind your authenticated caller, trusted resource and saved workflow history, then wrap the actual function. Setup has not performed or protected an application action.")
	}
	return nil
}
