package setup

import (
	"errors"
	"os"
)

func bindRuntime(directory, kind string) error {
	root, err := privateRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := readPrivate(root, "installation-kind")
	if errors.Is(err, os.ErrNotExist) {
		// Exclusive creation prevents concurrent native/Docker starts from creating
		// two unrelated state stores for one local installation.
		return createPrivate(root, "installation-kind", []byte(kind+"\n"))
	}
	if err != nil || string(data) != kind+"\n" {
		return errors.New("the saved installation uses a different runtime; review state migration before switching native and Docker")
	}
	return nil
}
