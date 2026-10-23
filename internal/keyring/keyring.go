package keyring

import (
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sys/unix"
)

// keyPosAll grants view, read, write, search, link and setattr to the
// possessor of a key only. x/sys/unix does not export the permission bits
// (see keyctl_setperm(3)).
const keyPosAll = 0x3f000000

// Keyring is a kernel keyring used to cache key passphrases.
//
// It is the thread keyring of the OS thread that created it, restricted to
// possessor-only permissions. A thread keyring is not findable by name, is
// not visible to or linkable by other processes of the same user, and is
// destroyed with the thread. A named session keyring, by contrast, is
// created with USR_VIEW|USR_READ|USR_LINK and any process running as the
// same user can link it into its own keyring and read the cached
// passphrases.
type Keyring struct {
	ringid int
}

// CreateThreadKeyring creates (or fetches) the thread keyring of the calling
// OS thread and restricts it to the possessor. The caller must be locked to
// its OS thread with runtime.LockOSThread, and all later operations on the
// returned Keyring must run on that same thread.
func CreateThreadKeyring() (*Keyring, error) {
	id, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_THREAD_KEYRING, true)
	if err != nil {
		return nil, fmt.Errorf("failed creating thread keyring: %w", err)
	}
	if err := unix.KeyctlSetperm(id, keyPosAll); err != nil {
		return nil, fmt.Errorf("failed restricting thread keyring: %w", err)
	}
	return &Keyring{ringid: id}, nil
}

func (k *Keyring) AddKey(name string, b []byte) error {
	return k.AddKeyWithTimeout(name, b, 0)
}

func (k *Keyring) AddKeyWithTimeout(name string, b []byte, timeout time.Duration) error {
	slog.Debug("addkey", slog.String("name", name))
	_, err := k.addKey(name, b, timeout)
	return err
}

// addKey adds the key and returns its serial so tests can probe it.
func (k *Keyring) addKey(name string, b []byte, timeout time.Duration) (int, error) {
	id, err := unix.AddKey("user", name, b, k.ringid)
	if err != nil {
		return 0, fmt.Errorf("failed add-key: %v", err)
	}
	// user keys are created with USR_VIEW; drop it so the key does not show
	// up in /proc/keys for other processes either.
	if err := unix.KeyctlSetperm(id, keyPosAll); err != nil {
		_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
		return 0, fmt.Errorf("failed restricting key: %v", err)
	}
	if timeout > 0 {
		if err := setKeyTimeout(id, timeout); err != nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
			return 0, err
		}
	}
	return id, nil
}

func (k *Keyring) ReadKey(name string) (*Key, error) {
	return k.ReadKeyWithTimeout(name, 0)
}

func (k *Keyring) ReadKeyWithTimeout(name string, timeout time.Duration) (*Key, error) {
	slog.Debug("readkey", slog.String("name", name))
	id, err := unix.KeyctlSearch(k.ringid, "user", name, 0)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		if err := setKeyTimeout(id, timeout); err != nil {
			return nil, err
		}
	}
	b, err := ReadKeyIntoMemory(id)
	if err != nil {
		return nil, err
	}
	return b, err
}

func (k *Keyring) RemoveKey(name string) error {
	slog.Debug("removekey", slog.String("name", name))
	id, err := unix.KeyctlSearch(k.ringid, "user", name, 0)
	if err != nil {
		return fmt.Errorf("failed remove-key: %v", err)
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
	return err
}

func setKeyTimeout(id int, timeout time.Duration) error {
	seconds := int((timeout + time.Second - 1) / time.Second)
	if seconds < 1 {
		return fmt.Errorf("key timeout must be at least 1 second")
	}
	_, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, id, seconds, 0, 0)
	if err != nil {
		return fmt.Errorf("failed set-key-timeout: %v", err)
	}
	return nil
}
