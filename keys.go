package xmlsec

import (
	"crypto"
	"crypto/x509"
)

// KeyProvider supplies the key material for signing.
//
// Signer's public key must correspond to Certificate. Signer is an
// interface rather than a concrete key type so that a PKCS#11 token, a
// cloud KMS key, and an in-process PEM key are interchangeable. Decryption
// takes its crypto.Decrypter or private key as an argument instead.
type KeyProvider struct {
	Signer      crypto.Signer
	Certificate *x509.Certificate
}
