package xmlsec

import (
	"crypto"
	"crypto/x509"
)

// KeyProvider supplies the key material for signing or decryption.
//
// Signer is used for signature generation; its public key must correspond
// to Certificate. Decrypter is used for XML decryption. Either may be nil
// if the corresponding operation is not performed.
//
// Both are interfaces rather than concrete key types so that a PKCS#11
// token, a cloud KMS key, and an in-process PEM key are interchangeable.
type KeyProvider struct {
	Signer      crypto.Signer
	Decrypter   crypto.Decrypter
	Certificate *x509.Certificate

	// Chain is the intermediate certificates, leaf first, excluding
	// Certificate itself. Used only when emitting an X509PKIPathv1
	// BinarySecurityToken.
	Chain []*x509.Certificate
}
