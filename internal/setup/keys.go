package setup

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"regexp"
)

var codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type applicationKey struct{ PublicPEM, Fingerprint string }

func checkConnection(directory, origin string, value connection) error {
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	root, err := privateRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := readPrivate(root, "connection.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var saved struct {
		FormatVersion  int    `json:"formatVersion"`
		APIURL         string `json:"apiUrl"`
		OrganisationID string `json:"organisationId"`
		DeploymentID   string `json:"deploymentId"`
	}
	if err != nil || json.Unmarshal(data, &saved) != nil || saved.FormatVersion != 1 ||
		saved.APIURL != origin || saved.OrganisationID != value.OrganisationID || saved.DeploymentID != value.DeploymentID {
		return errors.New("this private directory belongs to a different or unreadable connection; use its original deployment or a separate directory")
	}
	return nil
}

func privateRoot(directory string) (*os.Root, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("cannot create the private application directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("the application directory must be a private directory with mode 0700")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("cannot open the private application directory")
	}
	return root, nil
}

func readPrivate(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return nil, errors.New("application files must be private regular files; symlinks are not accepted")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("the application file changed while it was being opened")
	}
	return io.ReadAll(io.LimitReader(file, 8193))
}

func prepareKey(directory string) (applicationKey, error) {
	root, err := privateRoot(directory)
	if err != nil {
		return applicationKey{}, err
	}
	defer root.Close()
	privatePEM, err := readPrivate(root, "executor-private.pem")
	if errors.Is(err, os.ErrNotExist) {
		_, private, generationErr := ed25519.GenerateKey(rand.Reader)
		if generationErr != nil {
			return applicationKey{}, errors.New("cannot generate the application key")
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(private)
		if marshalErr != nil {
			return applicationKey{}, errors.New("cannot encode the application key")
		}
		privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		// Exclusive creation preserves an existing installation even if setup runs twice.
		if err := createPrivate(root, "executor-private.pem", privatePEM); err != nil {
			return applicationKey{}, err
		}
	} else if err != nil {
		return applicationKey{}, errors.New("cannot safely read the existing application key; no files were replaced")
	}
	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return applicationKey{}, errors.New("invalid existing application private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return applicationKey{}, errors.New("the existing application key must be Ed25519")
	}
	public := private.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return applicationKey{}, errors.New("cannot encode the public key")
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	previous, err := readPrivate(root, "executor-public.pem")
	if errors.Is(err, os.ErrNotExist) {
		if err := createPrivate(root, "executor-public.pem", publicPEM); err != nil {
			return applicationKey{}, err
		}
	} else if err != nil || string(previous) != string(publicPEM) {
		return applicationKey{}, errors.New("the saved public key does not match the private key; no files were replaced")
	}
	digest := sha256.Sum256(public)
	return applicationKey{PublicPEM: string(publicPEM), Fingerprint: hex.EncodeToString(digest[:])}, nil
}

func createPrivate(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create the application file without replacing an existing file")
	}
	_, writeErr := file.Write(data)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("could not save the application file; check the private directory before restarting setup")
	}
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("cannot retain the application directory safely")
	}
	defer directory.Close()
	// Persist the new directory entry before registering its public key remotely.
	if err := directory.Sync(); err != nil {
		return errors.New("cannot retain the application directory safely")
	}
	return nil
}

func saveConnection(directory, origin string, value connection, keySHA256 string) error {
	root, err := privateRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := json.MarshalIndent(struct {
		FormatVersion     int      `json:"formatVersion"`
		APIURL            string   `json:"apiUrl"`
		OrganisationID    string   `json:"organisationId"`
		DeploymentID      string   `json:"deploymentId"`
		TrustedPins       []string `json:"trustedKeyFingerprints"`
		ExecutorKeySHA256 string   `json:"executorKeySha256"`
	}{1, origin, value.OrganisationID, value.DeploymentID, value.TrustedPins, keySHA256}, "", "  ")
	if err != nil {
		return errors.New("cannot prepare the connection settings")
	}
	previous, err := readPrivate(root, "connection.json")
	if errors.Is(err, os.ErrNotExist) {
		return createPrivate(root, "connection.json", append(data, '\n'))
	}
	if err != nil {
		return errors.New("cannot safely read the existing connection settings")
	}
	if string(previous) != string(append(data, '\n')) {
		return errors.New("connection settings changed; existing files were preserved for review")
	}
	return nil
}
