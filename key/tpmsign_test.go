package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// recordingTPM captures every command sent to the TPM.
type recordingTPM struct {
	transport.TPMCloser
	commands [][]byte
}

func (r *recordingTPM) Send(input []byte) ([]byte, error) {
	r.commands = append(r.commands, bytes.Clone(input))
	return r.TPMCloser.Send(input)
}

func (r *recordingTPM) sawBytes(b []byte) bool {
	for _, c := range r.commands {
		if bytes.Contains(c, b) {
			return true
		}
	}
	return false
}

func TestSignPassphraseNotOnTheBus(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	tpm := &recordingTPM{TPMCloser: sim}

	// Long enough that it can not appear in a command by chance, but within
	// the 32 byte auth limit of a SHA256-named key.
	pin := []byte("correct horse battery 7f3a")
	digest := sha256.Sum256([]byte("message"))

	for _, c := range []struct {
		name string
		alg  tpm2.TPMAlgID
		bits int
	}{
		{"ecdsa", tpm2.TPMAlgECC, 256},
		{"rsa", tpm2.TPMAlgRSA, 2048},
	} {
		t.Run(c.name, func(t *testing.T) {
			k, err := NewSSHTPMKey(tpm, c.alg, c.bits, nil, keyfile.WithUserAuth(pin))
			if err != nil {
				t.Fatal(err)
			}
			// Key creation uses the library and is outside this test.
			tpm.commands = nil

			signer := k.Signer(&keyring.ThreadKeyring{},
				func() ([]byte, error) { return nil, nil },
				func() transport.TPMCloser { return tpm },
				func(*keyfile.TPMKey) ([]byte, *keyring.Key, error) { return pin, nil, nil })

			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if len(tpm.commands) == 0 {
				t.Fatal("no TPM commands recorded")
			}
			if tpm.sawBytes(pin) {
				t.Fatal("passphrase was sent to the TPM in cleartext")
			}

			pub := signer.Public()
			switch p := pub.(type) {
			case *ecdsa.PublicKey:
				if !ecdsa.VerifyASN1(p, digest[:], sig) {
					t.Fatal("ecdsa signature does not verify")
				}
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig); err != nil {
					t.Fatalf("rsa signature does not verify: %v", err)
				}
			default:
				t.Fatalf("unexpected public key %T", pub)
			}
		})
	}
}

func TestSignWrongPassphraseIsAuthFail(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, nil, keyfile.WithUserAuth([]byte("right")))
	if err != nil {
		t.Fatal(err)
	}
	signer := k.Signer(&keyring.ThreadKeyring{},
		func() ([]byte, error) { return nil, nil },
		func() transport.TPMCloser { return tpm },
		func(*keyfile.TPMKey) ([]byte, *keyring.Key, error) { return []byte("wrong"), nil, nil })

	digest := sha256.Sum256([]byte("message"))
	_, err = signTPMKey(tpm, k.TPMKey, nil, []byte("wrong"), digest[:], tpm2.TPMAlgSHA256, tpm2.TPMAlgECC)
	if !errors.Is(err, tpm2.TPMRCAuthFail) {
		t.Fatalf("expected TPM_RC_AUTH_FAIL so the cached passphrase gets evicted, got %v", err)
	}
	_ = signer
}
