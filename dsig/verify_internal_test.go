package dsig

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
)

// An empty allow-list means the default set; an algorithm outside it is
// accepted only when a list names it. Today the default sets are everything
// implemented.
func TestAllowedDefaultSet(t *testing.T) {
	const legacy = "urn:example:legacy"
	if err := allowed("signature", legacy, nil, defaultSignature); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("outside the default set, empty list: %v", err)
	}
	if err := allowed("signature", legacy, []string{legacy}, defaultSignature); err != nil {
		t.Fatalf("outside the default set, named: %v", err)
	}
	if err := allowed("signature", xmlsec.SigRSASHA256, []string{legacy}, defaultSignature); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("in the default set, not named: %v", err)
	}

	for _, s := range []string{xmlsec.SigRSASHA256, xmlsec.SigRSASHA384, xmlsec.SigRSASHA512,
		xmlsec.SigECDSASHA256, xmlsec.SigECDSASHA384, xmlsec.SigECDSASHA512} {
		if !defaultSignature(s) {
			t.Errorf("%s not in the default set", s)
		}
	}
	for _, d := range []string{xmlsec.DigestSHA256, xmlsec.DigestSHA384, xmlsec.DigestSHA512} {
		if !defaultDigest(d) {
			t.Errorf("%s not in the default set", d)
		}
	}
	for _, a := range []c14n.Algorithm{c14n.Inclusive10, c14n.Inclusive10WithComments, c14n.Exclusive10,
		c14n.Exclusive10WithComments, c14n.Inclusive11, c14n.Inclusive11WithComments} {
		if !defaultC14N(string(a)) {
			t.Errorf("%s not in the default set", a)
		}
	}
	if defaultSignature("http://www.w3.org/2000/09/xmldsig#rsa-sha1") || defaultDigest("http://www.w3.org/2000/09/xmldsig#sha1") || defaultC14N("urn:x") {
		t.Error("an unimplemented algorithm is in the default set")
	}
}
