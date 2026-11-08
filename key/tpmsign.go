package key

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"sync"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// tpmMutex serialises access to the TPM; parallel signing requests would
// otherwise fight over transient handles.
var tpmMutex sync.Mutex

// signTPMKey loads k under its parent and signs digest with it.
//
// keyfile.TPMKeySigner sends the user auth as a plain password session,
// which puts the passphrase on the TPM bus in cleartext alongside an
// encrypting HMAC session that only protects the digest. Here the passphrase
// is instead used as the auth value of a salted HMAC session: it never
// leaves the host, the salt is encrypted to the (freshly created) storage
// root key so the session key can not be derived from the bus traffic, and
// the digest is still parameter-encrypted.
func signTPMKey(tpm transport.TPMCloser, k *keyfile.TPMKey, ownerauth, auth, digest []byte, digestalg, signalg tpm2.TPMAlgID) ([]byte, error) {
	var err error

	tpmMutex.Lock()
	defer tpmMutex.Unlock()

	if k.Keytype.Equal(keyfile.OIDImportableKey) {
		k, err = keyfile.ImportTPMKey(tpm, k, ownerauth)
		if err != nil {
			return nil, fmt.Errorf("failed loading imported key for signing: %v", err)
		}
	} else if !k.Keytype.Equal(keyfile.OIDLoadableKey) {
		return nil, fmt.Errorf("not a loadable key")
	}

	if !k.HasSigner() {
		return nil, fmt.Errorf("key does not have a signer")
	}

	sess := keyfile.NewTPMSession(tpm)
	parent, err := keyfile.GetParentHandle(sess, k.Parent, ownerauth)
	if err != nil {
		return nil, err
	}
	defer sess.FlushHandle()

	// The salt for the auth session is encrypted to the parent, so read
	// back its public area.
	_, parentPub, err := keyfile.ReadPublic(tpm, parent.Handle)
	if err != nil {
		return nil, fmt.Errorf("failed reading parent public: %v", err)
	}

	handle, err := keyfile.LoadKeyWithParent(sess, *parent, k)
	if err != nil {
		return nil, err
	}
	defer keyfile.FlushHandle(tpm, handle)

	handle.Auth = tpm2.HMAC(tpm2.TPMAlgSHA256, 16,
		tpm2.Auth(auth),
		tpm2.AESEncryption(128, tpm2.EncryptIn),
		tpm2.Salted(parent.Handle, *parentPub))

	rsp, err := keyfile.TPMSign(tpm, *handle, digest, digestalg, k.KeySize(), signalg)
	if err != nil {
		return nil, err
	}
	return keyfile.EncodeSignatureASN1(rsp)
}

// signOpts maps crypto.SignerOpts onto the TPM digest and signature schemes.
// Mirrors keyfile.TPMKeySigner.Sign.
func signOpts(k *keyfile.TPMKey, digest []byte, opts crypto.SignerOpts) (digestalg, signalg tpm2.TPMAlgID, err error) {
	switch opts.HashFunc() {
	case 0:
		// p11-kit sends us hashfunc 0 but we can infer from length the correct hash
		switch len(digest) {
		case 32:
			digestalg = tpm2.TPMAlgSHA256
		case 48:
			digestalg = tpm2.TPMAlgSHA384
		case 64:
			digestalg = tpm2.TPMAlgSHA512
		default:
			return 0, 0, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
		}
	case crypto.SHA256:
		digestalg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		digestalg = tpm2.TPMAlgSHA384
	case crypto.SHA512:
		digestalg = tpm2.TPMAlgSHA512
	default:
		return 0, 0, fmt.Errorf("%s is not a supported hashing algorithm", opts.HashFunc())
	}

	signalg = k.KeyAlgo()
	if _, ok := opts.(*rsa.PSSOptions); ok {
		if signalg != tpm2.TPMAlgRSA {
			return 0, 0, fmt.Errorf("attempting to use PSSOptions with non-RSA (alg %x) key", signalg)
		}
		signalg = tpm2.TPMAlgRSAPSS
	}
	return digestalg, signalg, nil
}
