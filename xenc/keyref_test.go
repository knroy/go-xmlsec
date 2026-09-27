package xenc_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

func TestAddKeyReference(t *testing.T) {
	for _, c := range []struct {
		name, carried string
		refs          []string
		want          string
	}{
		{"one", "", []string{"k1"}, `</xenc:CipherData><xenc:ReferenceList><xenc:KeyReference URI="#k1"></xenc:KeyReference></xenc:ReferenceList></xenc:EncryptedKey>`},
		{"before CarriedKeyName", "n", []string{"k1", "k2"},
			`</xenc:CipherData><xenc:ReferenceList><xenc:KeyReference URI="#k1"></xenc:KeyReference><xenc:KeyReference URI="#k2"></xenc:KeyReference></xenc:ReferenceList><xenc:CarriedKeyName>n</xenc:CarriedKeyName>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
				KeyEncryptionKey: make([]byte, 16), CarriedKeyName: c.carried})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range c.refs {
				if err := ek.AddKeyReference(r); err != nil {
					t.Fatal(err)
				}
			}
			if s := dkString(t, ek.Element); !strings.Contains(s, c.want) {
				t.Fatalf("no %s in\n%s", c.want, s)
			}
		})
	}
	ek, _ := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: make([]byte, 16)})
	if err := ek.AddKeyReference("#k"); err == nil {
		t.Fatal("non-NCName accepted")
	}
}

// A chain of two EncryptedKeys (section 3.5.1): the data key wrapped under
// a KEK that a second EncryptedKey carries, found by FindEncryptedKey on
// each in turn, through DataReference and then KeyReference.
func TestEncryptedKeyChain(t *testing.T) {
	shared := bytes.Repeat([]byte{5}, 16)
	kek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES256GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: shared})
	if err != nil {
		t.Fatal(err)
	}
	data, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES256, KeyEncryptionKey: kek.SessionKey})
	if err != nil {
		t.Fatal(err)
	}
	xmltree.SetAttr(data.Element, "", "", "Id", "dk")
	if err := data.AddDataReference("ed"); err != nil {
		t.Fatal(err)
	}
	if err := kek.AddKeyReference("dk"); err != nil {
		t.Fatal(err)
	}
	doc := covParse(t, `<r xmlns="urn:example">`+dkString(t, data.Element)+dkString(t, kek.Element)+`<p>hello</p></r>`)
	out, err := xenc.EncryptElement(doc.Root(), firstNamed(doc, "p"), data.SessionKey, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DataID: "ed"})
	if err != nil {
		t.Fatal(err)
	}
	ed := firstNamed(covParse(t, string(out)), "EncryptedData")
	ek1, err := xenc.FindEncryptedKey(ed)
	if err != nil || ek1.AttrValue("Id") != "dk" {
		t.Fatalf("first hop: %v", err)
	}
	ek2, err := xenc.FindEncryptedKey(ek1)
	if err != nil {
		t.Fatalf("second hop: %v", err)
	}
	k2, err := xenc.UnwrapEncryptedKey(ek2, shared, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k1, err := xenc.UnwrapEncryptedKey(ek1, k2, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := xenc.DecryptData(ed, k1, xenc.DecryptOptions{}); err != nil || !strings.Contains(string(pt), ">hello</p>") {
		t.Fatalf("%q, %v", pt, err)
	}
}
