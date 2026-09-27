package security

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// chainDoc is a document of EncryptedKeys, each with the Id and ds:KeyInfo
// content given, the key it looks for being named by that KeyInfo.
func chainDoc(t *testing.T, keys ...[2]string) *xdm.Node {
	t.Helper()
	s := `<r xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:ds="` + xmlsec.NSDSig + `">`
	for _, k := range keys {
		s += `<xenc:EncryptedKey Id="` + k[0] + `"><xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/>` +
			`<ds:KeyInfo>` + k[1] + `</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`
	}
	return legacyParse(t, s+`</r>`)
}

func rm(id string) string {
	return `<ds:RetrievalMethod Type="` + xenc.TypeEncryptedKey + `" URI="#` + id + `"/>`
}

func byID(root *xdm.Node, id string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(root, func(e *xdm.Node) {
		if e.AttrValue("Id") == id {
			found = e
		}
	})
	return found
}

// FindEncryptedKey takes one hop, so a cycle of EncryptedKeys cannot make
// it loop: each call returns the next key, and a caller walking the chain
// bounds its own steps. A key naming itself is refused outright.
func TestEncryptedKeyChainsBounded(t *testing.T) {
	doc := chainDoc(t, [2]string{"a", rm("b")}, [2]string{"b", rm("a")}, [2]string{"s", rm("s")})
	a := byID(doc, "a")
	b, err := xenc.FindEncryptedKey(a)
	if err != nil || b.AttrValue("Id") != "b" {
		t.Fatalf("a: %v", err)
	}
	if back, err := xenc.FindEncryptedKey(b); err != nil || back != a {
		t.Fatalf("b: %v", err)
	}
	if _, err := xenc.FindEncryptedKey(byID(doc, "s")); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("self: %v", err)
	}
}

// Several RetrievalMethods, or one Id carried twice, must not let the
// attacker choose which key a receiver uses.
func TestKeyRetrievalAmbiguityRefused(t *testing.T) {
	for _, c := range []struct {
		name string
		doc  *xdm.Node
	}{
		{"RetrievalMethods to different keys", chainDoc(t, [2]string{"a", rm("b") + rm("c")}, [2]string{"b", ``}, [2]string{"c", ``})},
		{"Id carried twice", chainDoc(t, [2]string{"a", rm("b")}, [2]string{"b", ``}, [2]string{"b", ``})},
	} {
		t.Run(c.name, func(t *testing.T) {
			if k, err := xenc.FindEncryptedKey(byID(c.doc, "a")); !errors.Is(err, xmlsec.ErrAmbiguousID) || k != nil {
				t.Fatalf("got %v, %v", k, err)
			}
		})
	}
	dk := legacyParse(t, `<r xmlns:xenc="`+xmlsec.NSXEnc+`" xmlns:xenc11="`+xmlsec.NSXEnc11+`" xmlns:ds="`+xmlsec.NSDSig+`">`+
		`<xenc11:DerivedKey Id="d1"/><xenc11:DerivedKey Id="d2"/><xenc:EncryptedData Id="a"><ds:KeyInfo>`+
		`<ds:RetrievalMethod Type="`+xenc.TypeDerivedKey+`" URI="#d1"/><ds:RetrievalMethod Type="`+xenc.TypeDerivedKey+`" URI="#d2"/>`+
		`</ds:KeyInfo></xenc:EncryptedData></r>`)
	if k, err := xenc.FindDerivedKey(byID(dk, "a")); !errors.Is(err, xmlsec.ErrAmbiguousID) || k != nil {
		t.Fatalf("DerivedKey: %v, %v", k, err)
	}
}
