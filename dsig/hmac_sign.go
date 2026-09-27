package dsig

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/hashes"
)

// signatureMethod checks opts.SignatureAlgorithm against the key model
// opts selects and returns its hash: a public-key algorithm without
// HMACKey, an HMAC-SHA2 one with it (XML-DSig 6.3).
func signatureMethod(opts SignOptions) (crypto.Hash, error) {
	alg := opts.SignatureAlgorithm
	if len(opts.HMACKey) == 0 {
		switch {
		case hmacAlgorithms[alg] && alg != xmlsec.SigHMACSHA1:
			return 0, fmt.Errorf("%w: %s needs SignOptions.HMACKey", xmlsec.ErrUnsupportedAlgorithm, alg)
		case opts.HMACOutputLength != 0:
			return 0, fmt.Errorf("%w: HMACOutputLength without HMACKey", xmlsec.ErrMalformed)
		}
		if err := refuseLegacy(alg); err != nil {
			return 0, err
		}
		h, ok := hashes.Signature(alg)
		if !ok {
			return 0, fmt.Errorf("%w: signature %q", xmlsec.ErrUnsupportedAlgorithm, alg)
		}
		return h, nil
	}
	if alg == xmlsec.SigHMACSHA1 {
		return 0, refuseLegacy(alg)
	}
	if !hmacAlgorithms[alg] {
		return 0, fmt.Errorf("%w: SignOptions.HMACKey is set, and signature algorithm %q is not HMAC", xmlsec.ErrUnsupportedAlgorithm, alg)
	}
	h := legacySignatures[alg]
	full := 8 * h.Size()
	switch n := opts.HMACOutputLength; {
	case n != 0 && (n%8 != 0 || n > full || n < max(full/2, 80)):
		return 0, fmt.Errorf("%w: HMACOutputLength %d; it must be 0 or a multiple of 8 from %d to %d", xmlsec.ErrMalformed, n, max(full/2, 80), full)
	case len(opts.HMACKey) < h.Size():
		return 0, fmt.Errorf("%w: an HMAC key of %d octets for %s; it needs at least %d (RFC 2104 section 3)",
			xmlsec.ErrUnsupportedKeyInfo, len(opts.HMACKey), alg, h.Size())
	case opts.KeyInfo != KeyInfoNone:
		return 0, fmt.Errorf("%w: an HMAC signature describes no key in ds:KeyInfo; use KeyInfoNone", xmlsec.ErrUnsupportedKeyInfo)
	}
	return h, nil
}

// macValue is the SignatureValue of an HMAC: the MAC, truncated to bits
// when that is not zero.
func macValue(h hash.Hash, bits int) []byte {
	v := h.Sum(nil)
	if bits > 0 {
		v = v[:bits/8]
	}
	return v
}
