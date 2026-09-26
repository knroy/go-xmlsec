package xmlsec

import (
	"crypto"
	"testing"
)

func TestHashLookups(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) (crypto.Hash, bool)
		uri  string
		want crypto.Hash
		ok   bool
	}{
		{"signature", SignatureHash, SigECDSASHA384, crypto.SHA384, true},
		{"signature sha1", SignatureHash, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", 0, false},
		{"signature digest URI", SignatureHash, DigestSHA256, 0, false},
		{"digest", DigestHash, DigestSHA512, crypto.SHA512, true},
		{"digest sha1", DigestHash, "http://www.w3.org/2000/09/xmldsig#sha1", 0, false},
		{"digest empty", DigestHash, "", 0, false},
		{"mgf", MGFHash, MGF1SHA256, crypto.SHA256, true},
		{"mgf sha1", MGFHash, "http://www.w3.org/2009/xmlenc11#mgf1sha1", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if h, ok := c.fn(c.uri); h != c.want || ok != c.ok {
				t.Fatalf("got %v, %v", h, ok)
			}
		})
	}
}
