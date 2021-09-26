package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/go-piv/piv-go/piv"
	"gopkg.in/square/go-jose.v2"
)

var _ jose.OpaqueSigner = (*signer)(nil)

// OpaqueSigner is an interface that supports signing payloads with opaque
// private key(s). Private key operations preformed by implementors may, for
// example, occur in a hardware module. An OpaqueSigner may rotate signing keys
// transparently to the user of this interface.
type signer struct {
	yk   *piv.YubiKey
	slot piv.Slot
	pin  string
	cert *x509.Certificate
}

func newSigner(yk *piv.YubiKey, slot piv.Slot, pin string) (*signer, error) {
	// TODO - probably should manage our own public key, rather than just using
	// the attested one.
	cert, err := yk.Attest(slot)
	if err != nil {
		return nil, fmt.Errorf("attesting slot: %v", err)
	}
	return &signer{
		yk:   yk,
		slot: slot,
		pin:  pin,
		cert: cert,
	}, nil
}

// Public returns the public key of the current signing key.
func (s *signer) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{
		Key:       s.cert.PublicKey,
		KeyID:     "TODO", // derive from attestation?
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

// Algs returns a list of supported signing algorithms.
func (s *signer) Algs() []jose.SignatureAlgorithm {
	// most widely supported for OIDC
	return []jose.SignatureAlgorithm{jose.RS256}
}

// SignPayload signs a payload with the current signing key using the given
// algorithm.
func (s *signer) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	auth := piv.KeyAuth{PIN: s.pin}
	priv, err := s.yk.PrivateKey(piv.SlotAuthentication, s.cert, auth)
	if err != nil {
		return nil, fmt.Errorf("getting private key handle: %v", err)
	}
	hasher := crypto.SHA256.New()
	if _, err := hasher.Write(payload); err != nil {
		return nil, err
	}
	hashed := hasher.Sum(nil)

	out, err := priv.(crypto.Signer).Sign(rand.Reader, hashed, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing: %v", err)
	}

	return out, nil
}
