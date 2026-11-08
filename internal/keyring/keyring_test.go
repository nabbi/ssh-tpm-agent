package keyring

import (
	"bytes"
	"errors"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// newTestKeyring pins the test goroutine to its OS thread for the duration of
// the test, since Keyring is a thread keyring.
func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	keyring, err := CreateThreadKeyring()
	if err != nil {
		t.Fatalf("failed getting keyring: %v", err)
	}
	return keyring
}

func TestSaveAndGetData(t *testing.T) {
	keyring := newTestKeyring(t)

	b := []byte("test string")
	if err := keyring.AddKey("test", b); err != nil {
		t.Fatalf("err: %v", err)
	}

	bb, err := keyring.ReadKey("test")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(b, bb.Read()) {
		t.Fatalf("strings not equal")
	}
}

func TestNoKey(t *testing.T) {
	keyring := newTestKeyring(t)
	_, err := keyring.ReadKey("this.key.does.not.exist")
	if !errors.Is(err, syscall.ENOKEY) {
		t.Fatalf("err: %v", err)
	}
}

func TestRemoveKey(t *testing.T) {
	keyring := newTestKeyring(t)
	b := []byte("test string")
	if err := keyring.AddKey("test-2", b); err != nil {
		t.Fatalf("err: %v", err)
	}

	bb, err := keyring.ReadKey("test-2")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(b, bb.Read()) {
		t.Fatalf("strings not equal")
	}

	if err = keyring.RemoveKey("test-2"); err != nil {
		t.Fatalf("failed removing key: %v", err)
	}
	_, err = keyring.ReadKey("test-2")
	if !errors.Is(err, syscall.ENOKEY) {
		t.Fatalf("we can still read the key")
	}
}

// TestNotAccessibleFromOtherThread checks that a cached passphrase can not be
// read, searched for or linked away by code that does not possess the
// keyring. The keyring is created on a locked OS thread; the test goroutine
// necessarily runs on a different thread and therefore has the same access
// as any other process of this user.
func TestNotAccessibleFromOtherThread(t *testing.T) {
	type ids struct{ ring, key int }
	got := make(chan ids)
	done := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		kr, err := CreateThreadKeyring()
		if err != nil {
			errc <- err
			return
		}
		id, err := kr.addKey("fingerprint", []byte("secret passphrase"))
		if err != nil {
			errc <- err
			return
		}
		got <- ids{kr.ringid, id}
		<-done
	}()
	defer close(done)

	var k ids
	select {
	case err := <-errc:
		t.Fatal(err)
	case k = <-got:
	}

	if _, err := unix.KeyctlBuffer(unix.KEYCTL_READ, k.key, nil, 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("expected EACCES reading key from another thread, got %v", err)
	}
	if _, err := unix.KeyctlSearch(k.ring, "user", "fingerprint", 0); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("expected EACCES searching keyring from another thread, got %v", err)
	}
	for _, id := range []int{k.ring, k.key} {
		_, err := unix.KeyctlInt(unix.KEYCTL_LINK, id, unix.KEY_SPEC_USER_KEYRING, 0, 0)
		if !errors.Is(err, syscall.EACCES) {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, unix.KEY_SPEC_USER_KEYRING, 0, 0)
			t.Fatalf("expected EACCES linking %d into the user keyring, got %v", id, err)
		}
	}
}
