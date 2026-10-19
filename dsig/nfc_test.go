package dsig_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// decomposed is "é" as e and a combining acute accent: not NFC.
const decomposed = "é"

// XML-DSig 8.1.3: Sign refuses to sign non-NFC content, in a reference or
// in ds:SignedInfo itself.
func TestSignRefusesNonNFC(t *testing.T) {
	cases := []struct {
		name string
		text string
		typ  string
	}{
		{"reference", decomposed, ""},
		{"SignedInfo", "x", "urn:" + decomposed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(`<r><a xml:id="a">`+c.text+`</a></r>`))
			r := ref("#a")
			r.Type = c.typ
			_, err := signAt(&doc, newKey(t, rsaKey), dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References:                []dsig.Reference{r},
			})
			if !errors.Is(err, xmlsec.ErrNotNFC) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// nonNFCSignature signs #a after setting its text, and the Reference Type,
// neither of which Sign would accept when not NFC.
func nonNFCSignature(t *testing.T, text, typ string) (doc, sig *xdm.Node) {
	t.Helper()
	doc = parse(t, []byte(covDoc(covSI(covCM+covSM+covRef)+covSV)))
	sig = findSignature(doc)
	var e xmltree.Edits
	e.SetAttr(sig.ChildElements()[0].ChildElements()[2], xdm.QName{Local: "Type"}, typ)
	doc, sig = rebuilt(doc, sig, &e)
	a := xmltree.DocumentElement(doc).ChildElements()[0]
	a.FirstChild().SetValue(text)
	r := sig.ChildElements()[0].ChildElements()[2]
	h := sha256.New()
	if _, err := c14n.Digest(h, a, c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
		t.Fatal(err)
	}
	r.ChildElements()[2].FirstChild().SetValue(b64(h.Sum(nil)))
	resignSI(t, sig, c14n.Exclusive10)
	return doc, sig
}

// VerifyOptions.RequireNFC refuses what another signer produced over
// non-NFC content; without it, such a signature verifies.
func TestVerifyRequireNFC(t *testing.T) {
	cases := []struct {
		name, text, typ string
		want            error
	}{
		{"NFC", "é", "urn:x", nil},
		{"reference", decomposed, "urn:x", xmlsec.ErrNotNFC},
		{"SignedInfo", "x", "urn:" + decomposed, xmlsec.ErrNotNFC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := nonNFCSignature(t, c.text, c.typ)
			opts := dsig.VerifyOptions{PublicKey: &rsaKey.PublicKey}
			if _, err := dsig.Verify(doc, sig, opts); err != nil {
				t.Fatalf("without RequireNFC: %v", err)
			}
			opts.RequireNFC = true
			if _, err := dsig.Verify(doc, sig, opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
