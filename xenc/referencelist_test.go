package xenc_test

import (
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// rlDoc is a document holding a ReferenceList with refs, then rest.
func rlDoc(refs, rest string) string {
	return `<r ` + resolveNS + ` xmlns:wsse11="` + xmlsec.NSWSSE11 + `"><xenc:ReferenceList>` + refs + `</xenc:ReferenceList>` + rest + `</r>`
}

func dataRef(uri string) string { return `<xenc:DataReference URI="` + uri + `"/>` }

// SOAP Message Security 1.1.1 section 9.4.2: a header ReferenceList names
// the EncryptedData to decrypt, directly or through an EncryptedHeader.
func TestReferencedData(t *testing.T) {
	doc := covParse(t, rlDoc(dataRef("#a")+`<xenc:KeyReference URI="#k"/>`+dataRef("#h"),
		resolveED(`Id="a"`, `-`)+`<wsse11:EncryptedHeader wsu:Id="h">`+resolveED(`Id="b"`, `-`)+`</wsse11:EncryptedHeader>`))
	got, err := xenc.ReferencedData(firstNamed(doc, "ReferenceList"))
	if err != nil || len(got) != 2 || got[0].AttrValue("Id") != "a" || got[1].AttrValue("Id") != "b" ||
		!got[1].Parent.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
		t.Fatalf("%v, %v", got, err)
	}
}

func TestReferencedDataErrors(t *testing.T) {
	ed := resolveED(`Id="a"`, `-`)
	for _, c := range []struct {
		name, doc string
		want      error
	}{
		{"not a ReferenceList", `<r ` + resolveNS + `>` + ed + `</r>`, xmlsec.ErrMalformed},
		{"empty", rlDoc(``, ed), xmlsec.ErrMalformed},
		{"only KeyReference", rlDoc(`<xenc:KeyReference URI="#a"/>`, ed), xmlsec.ErrMalformed},
		{"other child", rlDoc(`<x/>`, ed), xmlsec.ErrMalformed},
		{"external URI", rlDoc(dataRef("http://example.com/a"), ed), xmlsec.ErrMalformed},
		{"empty fragment", rlDoc(dataRef("#"), ed), xmlsec.ErrMalformed},
		{"missing", rlDoc(dataRef("#b"), ed), xmlsec.ErrIDNotFound},
		{"duplicate ID", rlDoc(dataRef("#a"), ed+`<x wsu:Id="a"/>`), xmlsec.ErrAmbiguousID},
		{"not EncryptedData", rlDoc(dataRef("#a"), `<x wsu:Id="a"/>`), xmlsec.ErrMalformed},
		{"EncryptedHeader with two", rlDoc(dataRef("#h"), `<wsse11:EncryptedHeader wsu:Id="h">`+ed+resolveED(``, `-`)+`</wsse11:EncryptedHeader>`), xmlsec.ErrMalformed},
		{"listed twice", rlDoc(dataRef("#a")+dataRef("#a"), ed), xmlsec.ErrMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := xenc.ReferencedData(firstNamed(covParse(t, c.doc), "ReferenceList"))
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
		})
	}
	if _, err := xenc.ReferencedData(covParse(t, `<r `+resolveNS+`>`+ed+`</r>`).ChildElements()[0]); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatal(err)
	}
}
