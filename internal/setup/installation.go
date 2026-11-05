package setup

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// Installation runs a saved native connection or operates its verified Docker
// installation. Stop/remove retain volumes, credentials and Runtime history.
func Installation(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("use installation run|status|start|stop|remove --directory <private directory>")
	}
	action := args[0]
	if action != "run" && action != "status" && action != "start" && action != "stop" && action != "remove" {
		return errors.New("use installation run (native), status, start, stop or remove (Docker)")
	}
	flags := flag.NewFlagSet("installation "+action, flag.ContinueOnError)
	flags.SetOutput(output)
	directory := flags.String("directory", "", "private application configuration directory")
	listen := flags.String("listen", "127.0.0.1:7078", "private native sidecar listener")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *directory == "" || flags.NArg() != 0 {
		return errors.New("supply the installation's --directory")
	}
	if _, err := os.Lstat(*directory); err != nil {
		return errors.New("the private application directory does not exist")
	}
	root, err := privateRoot(*directory)
	if err != nil {
		return err
	}
	data, err := readPrivate(root, "connection.json")
	root.Close()
	var saved struct {
		FormatVersion  int      `json:"formatVersion"`
		APIURL         string   `json:"apiUrl"`
		OrganisationID string   `json:"organisationId"`
		DeploymentID   string   `json:"deploymentId"`
		TrustedPins    []string `json:"trustedKeyFingerprints"`
	}
	if err != nil || json.Unmarshal(data, &saved) != nil || saved.FormatVersion != 1 ||
		!identifier.MatchString(saved.OrganisationID) || !identifier.MatchString(saved.DeploymentID) ||
		len(saved.TrustedPins) < 1 || len(saved.TrustedPins) > 2 {
		return errors.New("the saved connection is invalid")
	}
	for _, pin := range saved.TrustedPins {
		if !fingerprint.MatchString(pin) {
			return errors.New("the saved signing pins are invalid")
		}
	}
	if action == "run" {
		return runNative(ctx, *directory, saved.APIURL, *listen, connection{OrganisationID: saved.OrganisationID,
			DeploymentID: saved.DeploymentID, TrustedPins: saved.TrustedPins}, output)
	}
	installation, err := dockerFor(*directory, saved.APIURL, connection{
		OrganisationID: saved.OrganisationID, DeploymentID: saved.DeploymentID, TrustedPins: saved.TrustedPins,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if action == "start" {
		return installation.start(ctx, output)
	}
	container, err := installation.inspect(ctx)
	if err != nil {
		return err
	}
	if container == nil {
		fmt.Fprintln(output, "No container is installed. Private settings and any retained volumes were left unchanged.")
		return nil
	}
	if action == "status" {
		fmt.Fprintln(output, "Container:", installation.container)
		fmt.Fprintln(output, "Process:", container.State.Status)
		if !container.State.Running {
			return nil
		}
		if _, err := dockerCommand(ctx, nil, "exec", container.ID, "/usr/local/bin/authrail-container", "health"); err != nil {
			return errors.New("the sidecar is running but has no usable signed rule bundle; inspect its deployment and logs")
		}
		fmt.Fprintln(output, "Signed rules: usable. Application enforcement and report delivery require separate checks.")
		return nil
	}
	fmt.Fprintln(output, "Stopping this sidecar; its protected application must be paused before making more tool calls.")
	if container.State.Running {
		if _, err := dockerCommand(ctx, nil, "stop", "--time", "15", container.ID); err != nil {
			return err
		}
	}
	if action == "remove" {
		if _, err := dockerCommand(ctx, nil, "rm", container.ID); err != nil {
			return err
		}
		fmt.Fprintln(output, "Removed this container. Both private volumes and all local connection files were retained.")
	} else {
		fmt.Fprintln(output, "Sidecar stopped. State, queued reports and credentials were retained.")
	}
	return nil
}
