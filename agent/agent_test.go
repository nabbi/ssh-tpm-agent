package agent_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"path"
	"testing"

	"github.com/foxboron/ssh-tpm-agent/agent"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/internal/keytest"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestAddKey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	socket := path.Join(t.TempDir(), "socket")
	unixList, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})

	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}
	defer unixList.Close()

	ag := agent.NewAgent(unixList,
		[]sshagent.ExtendedAgent{},
		// Keyring callback
		func() *keyring.ThreadKeyring { return &keyring.ThreadKeyring{} },
		// TPM Callback
		func() transport.TPMCloser { return tpm },
		// Owner password
		func() ([]byte, error) { return []byte(""), nil },
		// PIN Callback
		func(_ key.SSHTPMKeys) ([]byte, *keyring.Key, error) { return []byte(""), nil, nil },
	)
	defer ag.Stop()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := sshagent.NewClient(conn)

	k, err := key.NewSSHTPMKey(tpm, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}

	addedkey := sshagent.AddedKey{
		PrivateKey:  k,
		Certificate: nil,
		Comment:     k.Description,
	}

	_, err = client.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&addedkey))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSigning(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	ca := keytest.MkECDSA(t, elliptic.P256())
	for _, c := range []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		wanterr error
	}{
		{
			text: "sign key",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
			f:    keytest.MkKey,
		},
		{
			text: "sign key cert",
			alg:  tpm2.TPMAlgECC,
			bits: 256,
			f:    keytest.MkCertificate(t, &ca),
		},
	} {

		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			ag := keytest.NewTestAgent(t, tpm)
			defer ag.Stop()

			if err := ag.AddKey(k); err != nil {
				t.Fatalf("failed saving key: %v", err)
			}

			// Shim the certificate if there is one
			var sshkey ssh.PublicKey
			if k.Certificate != nil {
				sshkey = k.Certificate
			} else {
				sshkey = *k.PublicKey
			}

			_, err = ag.Sign(sshkey, []byte("test"))
			if !errors.Is(err, c.wanterr) {
				t.Fatalf("failed signing: %v", err)
			}
		})
	}
}

func TestRemoveCertFromProxy(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	caEcdsa, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed creating CA key")
	}

	for _, c := range []struct {
		text    string
		alg     tpm2.TPMAlgID
		bits    int
		f       keytest.KeyFunc
		wanterr error
		numkeys int
	}{
		{
			text:    "sign key",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			f:       keytest.MkKey,
			numkeys: 0,
		},
		{
			text:    "sign key cert",
			alg:     tpm2.TPMAlgECC,
			bits:    256,
			f:       keytest.MkCertificate(t, caEcdsa),
			numkeys: 1,
		},
	} {

		t.Run(c.text, func(t *testing.T) {
			k, err := c.f(t, tpm, c.alg, c.bits, []byte(""), "")
			if err != nil {
				t.Fatalf("failed key import: %v", err)
			}

			proxyagent := keytest.NewTestAgent(t, tpm)
			defer proxyagent.Stop()

			testagent := keytest.NewTestAgent(t, tpm)
			defer testagent.Stop()

			if err := testagent.AddKey(k); err != nil {
				t.Fatalf("failed saving key: %v", err)
			}

			if k.Certificate != nil {
				// If we have a certificate, include
				// the key without the certificate
				c := *k
				c.Certificate = nil
				if err := testagent.AddKey(&c); err != nil {
					t.Fatalf("failed saving key: %v", err)
				}
			}

			// Add testagent to proxyagent
			// We'll try to remove the key from testagent.
			proxyagent.AddProxyAgent(testagent)

			// Shim the certificate if there is one
			var sshkey ssh.PublicKey
			if k.Certificate != nil {
				sshkey = k.Certificate
			} else {
				sshkey = *k.PublicKey
			}

			if err := proxyagent.Remove(sshkey); err != nil {
				t.Fatalf("failed to remove key: %v", err)
			}

			// Check the key doesn't exist in the proxy nor the agent
			proxysl, err := proxyagent.List()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(proxysl) != c.numkeys {
				t.Fatalf("still keys in the agent. Should be 0")
			}

			sl, err := testagent.List()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(sl) != c.numkeys {
				t.Fatalf("still keys in the agent. Should be 0")
			}
		})
	}
}

// TestConfirmConstraintSticky checks that a client can not drop a key's
// confirm constraint by re-adding (or removing and re-adding) the key
// without the user's approval through SSH_ASKPASS.
func TestConfirmConstraintSticky(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// /bin/false denies, /bin/true approves; both work as SSH_ASKPASS
	// programs for confirm prompts, which only look at the exit code.
	t.Setenv("SSH_ASKPASS_REQUIRE", "force")
	t.Setenv("SSH_ASKPASS", "/bin/false")

	k, err := keytest.MkKey(t, tpm, tpm2.TPMAlgECC, 256, []byte(""), "")
	if err != nil {
		t.Fatal(err)
	}

	ag := keytest.NewTestAgent(t, tpm)
	defer ag.Stop()

	addKey := func(confirm bool) error {
		_, err := ag.Extension(agent.SSH_TPM_AGENT_ADD, agent.MarshalTPMKeyMsg(&sshagent.AddedKey{
			PrivateKey:       k,
			ConfirmBeforeUse: confirm,
		}))
		return err
	}

	// Victim adds the key with -c; signing is denied by askpass.
	if err := addKey(true); err != nil {
		t.Fatal(err)
	}
	if _, err := ag.Sign(*k.PublicKey, []byte("test")); !errors.Is(err, agent.ErrUserDeniedConfirm) {
		t.Fatalf("expected ErrUserDeniedConfirm with constraint, got %v", err)
	}

	// Another client re-adds the same key without the constraint; the user
	// declines, so the add is refused and signing still asks.
	if err := addKey(false); !errors.Is(err, agent.ErrConfirmConstraintKept) {
		t.Fatalf("expected ErrConfirmConstraintKept, got %v", err)
	}
	if _, err := ag.Sign(*k.PublicKey, []byte("test")); !errors.Is(err, agent.ErrUserDeniedConfirm) {
		t.Fatalf("expected ErrUserDeniedConfirm after refused re-add, got %v", err)
	}

	// Removing the key first does not help either.
	if err := ag.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if err := addKey(false); !errors.Is(err, agent.ErrConfirmConstraintKept) {
		t.Fatalf("expected ErrConfirmConstraintKept after RemoveAll, got %v", err)
	}
	keys, _ := ag.List()
	if len(keys) != 0 {
		t.Fatalf("refused key must not be loaded, got %d keys", len(keys))
	}

	// Without an askpass program at all the constraint is kept as well.
	t.Setenv("SSH_ASKPASS", "/nonexistent/askpass")
	if err := addKey(false); !errors.Is(err, agent.ErrConfirmConstraintKept) {
		t.Fatalf("expected ErrConfirmConstraintKept without askpass, got %v", err)
	}

	// When the user approves, the constraint is dropped and signing no
	// longer consults askpass even though it would deny.
	t.Setenv("SSH_ASKPASS", "/bin/true")
	if err := addKey(false); err != nil {
		t.Fatalf("expected approved re-add to succeed, got %v", err)
	}
	t.Setenv("SSH_ASKPASS", "/bin/false")
	if _, err := ag.Sign(*k.PublicKey, []byte("test")); err != nil {
		t.Fatalf("expected signing without constraint to succeed, got %v", err)
	}
}

// TestMalformedAddKeyDoesNotCrash sends tpm-add-key messages without a
// private key, with and without a certificate. Both used to dereference a
// nil key (immediately, or on the next List) and kill the agent process.
func TestMalformedAddKeyDoesNotCrash(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	k, err := keytest.MkKey(t, tpm, tpm2.TPMAlgECC, 256, []byte(""), "")
	if err != nil {
		t.Fatal(err)
	}
	ca := keytest.MkECDSA(t, elliptic.P256())
	certKey, err := keytest.MkCertificate(t, &ca)(t, tpm, tpm2.TPMAlgECC, 256, []byte(""), "")
	if err != nil {
		t.Fatal(err)
	}

	ag := keytest.NewTestAgent(t, tpm)
	defer ag.Stop()
	if err := ag.AddKey(k); err != nil {
		t.Fatal(err)
	}

	for _, msg := range []agent.TPMKeyMsg{
		{Type: "TPMKEY"},
		{Type: "TPMKEY", CertBytes: certKey.Certificate.Marshal()},
		{Type: "TPMKEY", Constraints: []byte{2}},
	} {
		_, err := ag.Extension(agent.SSH_TPM_AGENT_ADD, ssh.Marshal(msg))
		if !errors.Is(err, agent.ErrNoPrivateKey) {
			t.Fatalf("expected ErrNoPrivateKey, got %v", err)
		}
	}

	keys, err := ag.List()
	if err != nil {
		t.Fatalf("List failed after malformed add: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected the one real key, got %d", len(keys))
	}
}
