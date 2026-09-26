package xenc_test

import (
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

const resolveNS = `xmlns:xenc="` + xenc.NSXEnc + `" xmlns:ds="` + xenc.NSDSig + `" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"`

// resolveEK is an EncryptedKey with the given attributes and trailing
// children.
func resolveEK(attrs, rest string) string {
	return `<xenc:EncryptedKey ` + attrs + `><xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/>` +
		`<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData>` + rest + `</xenc:EncryptedKey>`
}

func resolveED(attrs, keyInfo string) string {
	ki := ""
	if keyInfo != "-" {
		ki = `<ds:KeyInfo>` + keyInfo + `</ds:KeyInfo>`
	}
	return `<xenc:EncryptedData ` + attrs + `><xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128GCM + `"/>` + ki +
		`<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`
}

// Section 3.5: an inline EncryptedKey, a same-document RetrievalMethod,
// a KeyName matching a CarriedKeyName, or a ReferenceList naming the
// EncryptedData.
func TestFindEncryptedKey(t *testing.T) {
	const rm = `<ds:RetrievalMethod Type="` + xenc.TypeEncryptedKey + `" URI="#ek"/>`
	const refList = `<xenc:ReferenceList><xenc:KeyReference URI="#ed"/><xenc:DataReference URI="#other"/><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`
	for _, c := range []struct {
		name, doc string
	}{
		{"inline", `<r ` + resolveNS + `>` + resolveEK(`Id="decoy"`, ``) + resolveED(``, resolveEK(`Id="want"`, ``)) + `</r>`},
		{"RetrievalMethod by Id", `<r ` + resolveNS + `>` + resolveEK(`Id="ek" Recipient="want"`, ``) + resolveED(``, rm) + `</r>`},
		{"RetrievalMethod by wsu:Id", `<r ` + resolveNS + `>` + resolveEK(`wsu:Id="ek" Recipient="want"`, ``) + resolveED(``, rm) + `</r>`},
		{"KeyName", `<r ` + resolveNS + `>` + resolveEK(`Id="n1"`, `<xenc:CarriedKeyName>Sally</xenc:CarriedKeyName>`) +
			resolveEK(`Id="want"`, `<xenc:CarriedKeyName> Sally Doe </xenc:CarriedKeyName>`) + resolveED(``, `<ds:KeyName> Sally Doe </ds:KeyName>`) + `</r>`},
		{"ReferenceList", `<r ` + resolveNS + `>` + resolveEK(`Id="n1"`, `<xenc:ReferenceList><xenc:DataReference URI="#other"/></xenc:ReferenceList>`) +
			resolveEK(`Id="want"`, refList) + resolveED(`Id="ed"`, `-`) + resolveED(`Id="other"`, `-`) + `</r>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedData"))
			if err != nil {
				t.Fatal(err)
			}
			if ek.AttrValue("Id") != "want" && ek.AttrValue("Recipient") != "want" {
				t.Fatalf("found %v", ek.Attrs)
			}
		})
	}
}

func TestFindEncryptedKeyErrors(t *testing.T) {
	rm := func(attrs, body string) string {
		return `<ds:RetrievalMethod ` + attrs + `>` + body + `</ds:RetrievalMethod>`
	}
	typ := `Type="` + xenc.TypeEncryptedKey + `"`
	ekRef := resolveEK(`Id="ek"`, ``)
	for _, c := range []struct {
		name, doc string
		want      error
	}{
		{"not EncryptedData", resolveEK(resolveNS, ``), xmlsec.ErrMalformed},
		{"empty KeyInfo", `<r ` + resolveNS + `>` + resolveED(``, ``) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"two KeyInfo children", `<r ` + resolveNS + `>` + resolveED(``, `<ds:KeyName>a</ds:KeyName><ds:KeyName>a</ds:KeyName>`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Data", `<r ` + resolveNS + `>` + resolveED(``, `<ds:X509Data/>`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"AgreementMethod on the data", `<r ` + resolveNS + `>` + resolveED(``, `<xenc:AgreementMethod/>`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod without Type", `<r ` + resolveNS + `>` + ekRef + resolveED(``, rm(`URI="#ek"`, ``)) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod to DerivedKey", `<r ` + resolveNS + `>` + ekRef + resolveED(``, rm(`URI="#ek" Type="http://www.w3.org/2009/xmlenc11#DerivedKey"`, ``)) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod external", `<r ` + resolveNS + `>` + ekRef + resolveED(``, rm(`URI="http://example.com/ek" `+typ, ``)) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod transforms", `<r ` + resolveNS + `>` + ekRef + resolveED(``, rm(`URI="#ek" `+typ, `<ds:Transforms/>`)) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod missing", `<r ` + resolveNS + `>` + resolveED(``, rm(`URI="#ek" `+typ, ``)) + `</r>`, xmlsec.ErrIDNotFound},
		{"RetrievalMethod duplicate", `<r ` + resolveNS + `>` + ekRef + resolveEK(`wsu:Id="ek"`, ``) + resolveED(``, rm(`URI="#ek" `+typ, ``)) + `</r>`, xmlsec.ErrAmbiguousID},
		{"RetrievalMethod chain", `<r ` + resolveNS + `>` + `<ds:KeyInfo Id="ek">` + rm(`URI="#k2" `+typ, ``) + `</ds:KeyInfo>` + resolveEK(`Id="k2"`, ``) +
			resolveED(``, rm(`URI="#ek" `+typ, ``)) + `</r>`, xmlsec.ErrMalformed},
		{"KeyName unmatched", `<r ` + resolveNS + `>` + resolveEK(``, `<xenc:CarriedKeyName>b</xenc:CarriedKeyName>`) + resolveED(``, `<ds:KeyName>a</ds:KeyName>`) + `</r>`, xmlsec.ErrIDNotFound},
		{"KeyName twice", `<r ` + resolveNS + `>` + resolveEK(``, `<xenc:CarriedKeyName>a</xenc:CarriedKeyName>`) + resolveEK(``, `<xenc:CarriedKeyName>a</xenc:CarriedKeyName>`) +
			resolveED(``, `<ds:KeyName>a</ds:KeyName>`) + `</r>`, xmlsec.ErrAmbiguousID},
		{"no KeyInfo and no Id", `<r ` + resolveNS + `>` + resolveED(``, `-`) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
		{"no reference", `<r ` + resolveNS + `>` + resolveEK(``, ``) + resolveED(`Id="ed"`, `-`) + `</r>`, xmlsec.ErrIDNotFound},
		{"two references", `<r ` + resolveNS + `>` + resolveEK(``, `<xenc:ReferenceList><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`) +
			resolveEK(``, `<xenc:ReferenceList><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`) + resolveED(`Id="ed"`, `-`) + `</r>`, xmlsec.ErrAmbiguousID},
		{"duplicate data Id", `<r ` + resolveNS + `>` + resolveEK(``, `<xenc:ReferenceList><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`) +
			resolveED(`Id="ed"`, `-`) + `<x wsu:Id="ed"/></r>`, xmlsec.ErrAmbiguousID},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedData"))
			if !errors.Is(err, c.want) || ek != nil {
				t.Fatalf("got %v, %v; want %v", ek, err, c.want)
			}
		})
	}
	if _, err := xenc.FindEncryptedKey(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatal(err)
	}
}
