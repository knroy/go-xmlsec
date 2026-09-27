// Package hashes maps the secure algorithm URIs of the root package to their
// hashes.
package hashes

import (
	"crypto"

	"github.com/knroy/go-xmlsec"
)

var signatureHashes = map[string]crypto.Hash{
	xmlsec.SigRSASHA256:   crypto.SHA256,
	xmlsec.SigRSASHA384:   crypto.SHA384,
	xmlsec.SigRSASHA512:   crypto.SHA512,
	xmlsec.SigECDSASHA256: crypto.SHA256,
	xmlsec.SigECDSASHA384: crypto.SHA384,
	xmlsec.SigECDSASHA512: crypto.SHA512,
}

var digestHashes = map[string]crypto.Hash{
	xmlsec.DigestSHA256: crypto.SHA256,
	xmlsec.DigestSHA384: crypto.SHA384,
	xmlsec.DigestSHA512: crypto.SHA512,
}

var mgfHashes = map[string]crypto.Hash{
	xmlsec.MGF1SHA224: crypto.SHA224,
	xmlsec.MGF1SHA256: crypto.SHA256,
	xmlsec.MGF1SHA384: crypto.SHA384,
	xmlsec.MGF1SHA512: crypto.SHA512,
}

// Signature returns the hash a Sig* algorithm signs over, and false for
// any URI that is not a secure Sig* constant.
func Signature(uri string) (crypto.Hash, bool) {
	h, ok := signatureHashes[uri]
	return h, ok
}

// Digest returns the hash for a secure Digest* URI, and false for any
// other.
func Digest(uri string) (crypto.Hash, bool) {
	h, ok := digestHashes[uri]
	return h, ok
}

// MGF returns the hash for a secure MGF1* URI, and false for any other.
func MGF(uri string) (crypto.Hash, bool) {
	h, ok := mgfHashes[uri]
	return h, ok
}
