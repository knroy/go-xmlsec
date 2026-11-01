// Package keysize bounds a received public key before any arithmetic is
// done with it: RSA verification costs grow with the cube of the modulus
// length, and nothing in crypto/rsa or crypto/x509 caps it.
package keysize

import (
	"fmt"

	"github.com/knroy/go-xmlsec/v2"
)

// MaxRSABits is the largest RSA modulus accepted, OpenSSL's limit
// (OPENSSL_RSA_MAX_MODULUS_BITS). Every deployed key is far below it.
const MaxRSABits = 16384

// CheckRSA refuses an RSA modulus of more than MaxRSABits bits with
// xmlsec.ErrUnsupportedKeyInfo. bits may be an upper bound, such as eight
// times the length of the encoded modulus, so that an oversized value is
// refused before it is decoded into a big.Int.
func CheckRSA(bits int) error {
	if bits > MaxRSABits {
		return fmt.Errorf("%w: %d-bit RSA key; at most %d bits accepted", xmlsec.ErrUnsupportedKeyInfo, bits, MaxRSABits)
	}
	return nil
}
