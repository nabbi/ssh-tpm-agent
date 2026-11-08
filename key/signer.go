package key

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
)

// Shim for keyfile.TPMKeySigner
// We need access to the SSHTPMKey to change the userauth for caching
type SSHKeySigner struct {
	key       SSHTPMKeys
	keyring   *keyring.ThreadKeyring
	tpm       func() transport.TPMCloser
	ownerauth func() ([]byte, error)

	// auth returns the userauth bytes along with the locked buffer backing
	// them if present.
	auth func(*keyfile.TPMKey) ([]byte, *keyring.Key, error)
}

var _ crypto.Signer = &SSHKeySigner{}

func (t *SSHKeySigner) Public() crypto.PublicKey {
	pk, err := t.key.GetTPMKey().PublicKey()
	// This shouldn't happen!
	if err != nil {
		panic(fmt.Errorf("failed producing public: %v", err))
	}
	return pk
}

func (t *SSHKeySigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var b []byte
	var err error
	switch key := t.key.(type) {
	case *HierSSHTPMKey:
		var digestalg tpm2.TPMAlgID
		switch opts.HashFunc() {
		case crypto.SHA256:
			digestalg = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			digestalg = tpm2.TPMAlgSHA384
		case crypto.SHA512:
			digestalg = tpm2.TPMAlgSHA512
		default:
			return nil, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
		}
		b, err = key.Sign(t.tpm(), []byte(nil), []byte(nil), digest, digestalg)
	case *SSHTPMKey:
		b, err = t.signKey(key, r, digest, opts)
	default:
		return nil, fmt.Errorf("this should not happen")
	}

	if errors.Is(err, tpm2.TPMRCAuthFail) {
		slog.Debug("removed cached userauth for key", slog.Any("err", err), slog.String("desc", t.key.GetDescription()))
		t.keyring.RemoveKey(t.key.Fingerprint())
	}
	return b, err
}

// signKey signs with the TPM key, passing the user auth through a salted
// HMAC session (see signTPMKey). The auth buffer is wiped and freed before
// signKey returns.
func (t *SSHKeySigner) signKey(k *SSHTPMKey, _ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digestalg, signalg, err := signOpts(k.TPMKey, digest, opts)
	if err != nil {
		return nil, err
	}

	auth := []byte("")
	if k.HasAuth() {
		p, box, err := t.auth(k.TPMKey)
		if box != nil {
			defer func() {
				if err := box.Free(); err != nil {
					slog.Error("failed to release pin storage", slog.Any("err", err))
				}
			}()
		}
		if err != nil {
			return nil, err
		}
		auth = p
	}

	ownerauth, err := t.ownerauth()
	if err != nil {
		return nil, err
	}

	return signTPMKey(t.tpm(), k.TPMKey, ownerauth, auth, digest, digestalg, signalg)
}

func NewSSHKeySigner(k SSHTPMKeys, keyring *keyring.ThreadKeyring, ownerAuth func() ([]byte, error), tpm func() transport.TPMCloser, auth func(*keyfile.TPMKey) ([]byte, *keyring.Key, error)) *SSHKeySigner {
	return &SSHKeySigner{
		keyring:   keyring,
		tpm:       tpm,
		ownerauth: ownerAuth,
		auth:      auth,
		key:       k,
	}
}
