package hashes

import (
	"crypto"
	"testing"

	"github.com/knroy/go-xmlsec"
)

func TestHashLookups(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) (crypto.Hash, bool)
		uri  string
		want crypto.Hash
		ok   bool
	}{
		{"signature", Signature, xmlsec.SigECDSASHA384, crypto.SHA384, true},
		// The legacy, verification-only algorithms are never returned: they
		// are neither signable nor in any default set.
		{"signature rsa-sha1", Signature, xmlsec.SigRSASHA1, 0, false},
		{"signature dsa-sha1", Signature, xmlsec.SigDSASHA1, 0, false},
		{"signature hmac-sha256", Signature, xmlsec.SigHMACSHA256, 0, false},
		{"signature digest URI", Signature, xmlsec.DigestSHA256, 0, false},
		{"digest", Digest, xmlsec.DigestSHA512, crypto.SHA512, true},
		{"digest sha1", Digest, xmlsec.DigestSHA1, 0, false},
		{"digest empty", Digest, "", 0, false},
		{"mgf", MGF, xmlsec.MGF1SHA256, crypto.SHA256, true},
		{"mgf sha224", MGF, xmlsec.MGF1SHA224, crypto.SHA224, true},
		{"mgf sha1", MGF, "http://www.w3.org/2009/xmlenc11#mgf1sha1", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if h, ok := c.fn(c.uri); h != c.want || ok != c.ok {
				t.Fatalf("got %v, %v", h, ok)
			}
		})
	}
}
