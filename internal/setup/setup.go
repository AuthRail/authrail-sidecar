package setup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
)

// Run confirms one deployment, registers locally saved keys/credentials and can
// start its sidecar. Setup access remains in memory; private keys stay local.
func Run(ctx context.Context, args []string, output io.Writer) error {
	parentCtx := ctx
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(output)
	api := flags.String("api-url", os.Getenv("AUTHRAIL_SETUP_API_URL"), "AuthRail API origin")
	directory := flags.String("directory", "", "private application configuration directory (default: user config/authrail/deployments/deployment ID)")
	noBrowser := flags.Bool("no-browser", false, "print the sign-in address without opening a browser")
	listen := flags.String("listen", "127.0.0.1:7078", "private native sidecar listener")
	runtimeMode := flags.String("runtime", "connection", "connection saves private settings; native runs beside a host application; docker starts a private container")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup does not accept positional arguments")
	}
	if *runtimeMode != "connection" && *runtimeMode != "docker" && *runtimeMode != "native" {
		return errors.New("use --runtime connection, --runtime native or --runtime docker")
	}
	c, err := newClient(*api)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	page, err := c.browserURL(ctx)
	if err != nil {
		return err
	}
	verifier, state := randomValue(), randomValue()
	challenge := sha256.Sum256([]byte(verifier))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot open the local sign-in callback")
	}
	callback := "http://" + listener.Addr().String() + "/runtime/setup/callback"
	code := make(chan string, 1)
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, MaxHeaderBytes: 4096,
		Handler: callbackHandler(callback, state, code)}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	query := url.Values{"redirectUri": {callback}, "state": {state},
		"codeChallenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	page.RawQuery = query.Encode()
	fmt.Fprintln(output, "Sign in to AuthRail and choose the deployment for this application:")
	fmt.Fprintln(output, page.String())
	if !*noBrowser {
		openBrowser(ctx, page.String())
	}
	select {
	case value := <-code:
		if err := c.exchange(ctx, value, verifier, callback); err != nil {
			return err
		}
	case <-ctx.Done():
		return errors.New("setup was cancelled or sign-in timed out; start setup again")
	}
	_ = server.Close()
	connection, err := c.connection(ctx)
	if err != nil {
		return err
	}
	if *directory == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return errors.New("cannot find a private configuration directory; supply --directory")
		}
		*directory = filepath.Join(base, "authrail", "deployments", connection.DeploymentID)
	}
	if err := checkConnection(*directory, c.origin, connection); err != nil {
		return err
	}
	key, err := prepareKey(*directory)
	if err != nil {
		return err
	}
	for _, registered := range connection.ExecutorKeys {
		if registered.Status == "current" && registered.SHA256 != key.Fingerprint {
			return errors.New("this deployment has a different application key; use its existing private key or review a key rotation in AuthRail")
		}
	}
	var registered struct {
		Fingerprint string `json:"keySha256"`
	}
	// Bind the directory before a remote change so an interrupted setup cannot
	// later attach these files to a different deployment.
	if err := saveConnection(*directory, c.origin, connection, key.Fingerprint); err != nil {
		return err
	}
	if err := c.request(ctx, http.MethodPost, "/runtime/setup/executor-key",
		map[string]string{"publicKeyPem": key.PublicPEM}, &registered); err != nil {
		return err
	}
	if registered.Fingerprint != key.Fingerprint {
		return errors.New("AuthRail registered an unexpected application key")
	}
	token, err := prepareCredentials(*directory)
	if err != nil {
		return err
	}
	if err := c.registerCredential(ctx, token, key.Fingerprint); err != nil {
		return err
	}
	fmt.Fprintln(output, "Application key registered. Private connection files saved in:")
	fmt.Fprintln(output, *directory)
	fmt.Fprintln(output, "Deployment and adapter credentials saved privately.")
	if *runtimeMode == "native" {
		return runNative(parentCtx, *directory, c.origin, *listen, connection, output)
	}
	if *runtimeMode == "docker" {
		installation, err := dockerFor(*directory, c.origin, connection)
		if err != nil {
			return err
		}
		return installation.start(ctx, output)
	}
	fmt.Fprintln(output, "No sidecar was started. Use --runtime docker for an application that runs in containers.")
	return nil
}

func randomValue() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		panic("system randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func callbackHandler(callback, state string, code chan<- string) http.Handler {
	uri, _ := url.Parse(callback)
	var received atomic.Bool
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		query, err := url.ParseQuery(r.URL.RawQuery)
		if r.Method != http.MethodGet || r.Host != uri.Host || r.URL.Path != uri.Path || err != nil ||
			len(query) != 2 || len(query["state"]) != 1 || len(query["code"]) != 1 ||
			subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 ||
			!codePattern.MatchString(query.Get("code")) {
			http.Error(w, "This sign-in does not match the terminal setup request.", http.StatusBadRequest)
			return
		}
		if !received.CompareAndSwap(false, true) {
			http.Error(w, "This setup callback was already received.", http.StatusConflict)
			return
		}
		select {
		case code <- query.Get("code"):
			fmt.Fprintln(w, "Return to your terminal to finish connecting AuthRail.")
		default:
			http.Error(w, "This setup callback was already received.", http.StatusConflict)
		}
	})
}

func openBrowser(ctx context.Context, address string) {
	var command *exec.Cmd
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "darwin":
		command = exec.CommandContext(ctx, "open", address)
	case "linux":
		command = exec.CommandContext(ctx, "xdg-open", address)
	default:
		return
	}
	// The printed address remains usable when no desktop/browser is available.
	_ = command.Run()
}
