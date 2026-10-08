package xenc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

const resolveNS = `xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:ds="` + xmlsec.NSDSig + `" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"`

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

// Sections 3.5.1 and 3.6: an EncryptedKey whose KEK another EncryptedKey
// carries, found through its own KeyInfo, or by the KeyReference, not the
// DataReference, of the other's ReferenceList.
func TestFindEncryptedKeyOfEncryptedKey(t *testing.T) {
	const rm = `<ds:RetrievalMethod Type="` + xenc.TypeEncryptedKey + `" URI="#kek"/>`
	target := func(ki string) string { // the EncryptedKey whose key is sought
		if ki != "" {
			ki = `<ds:KeyInfo>` + ki + `</ds:KeyInfo>`
		}
		return `<xenc:EncryptedKey Id="ek" Recipient="target"><xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/>` + ki +
			`<xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`
	}
	for _, c := range []struct {
		name, doc string
	}{
		{"inline", `<r ` + resolveNS + `>` + target(resolveEK(`Id="want"`, ``)) + `</r>`},
		{"RetrievalMethod", `<r ` + resolveNS + `>` + target(rm) + resolveEK(`Id="kek" Recipient="want"`, ``) + `</r>`},
		{"two RetrievalMethods to one", `<r ` + resolveNS + `>` + target(rm+rm) + resolveEK(`Id="kek" Recipient="want"`, ``) + `</r>`},
		{"KeyName", `<r ` + resolveNS + `>` + target(`<ds:KeyName>k</ds:KeyName>`) + resolveEK(`Id="want"`, `<xenc:CarriedKeyName>k</xenc:CarriedKeyName>`) + `</r>`},
		{"KeyReference", `<r ` + resolveNS + `>` + target(``) + resolveEK(`Id="decoy"`, `<xenc:ReferenceList><xenc:DataReference URI="#ek"/></xenc:ReferenceList>`) +
			resolveEK(`Id="want"`, `<xenc:ReferenceList><xenc:KeyReference URI="#ek"/></xenc:ReferenceList>`) + `</r>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedKey"))
			if err != nil {
				t.Fatal(err)
			}
			if ek.AttrValue("Id") != "want" && ek.AttrValue("Recipient") != "want" {
				t.Fatalf("found %v", ek.Attrs)
			}
		})
	}
	// One hop: the RetrievalMethod's target is returned, not followed; an
	// EncryptedKey naming itself is refused, and its own CarriedKeyName or
	// KeyReference does not match it.
	for _, c := range []struct {
		name, doc string
		want      error
	}{
		{"self by RetrievalMethod", `<r ` + resolveNS + `>` + target(`<ds:RetrievalMethod Type="`+xenc.TypeEncryptedKey+`" URI="#ek"/>`) + `</r>`, xmlsec.ErrMalformed},
		{"self by KeyName", `<r ` + resolveNS + `>` + strings.Replace(target(`<ds:KeyName>k</ds:KeyName>`), `</xenc:CipherData>`, `</xenc:CipherData><xenc:CarriedKeyName>k</xenc:CarriedKeyName>`, 1) + `</r>`, xmlsec.ErrIDNotFound},
		{"self by KeyReference", `<r ` + resolveNS + `>` + strings.Replace(target(``), `</xenc:CipherData>`, `</xenc:CipherData><xenc:ReferenceList><xenc:KeyReference URI="#ek"/></xenc:ReferenceList>`, 1) + `</r>`, xmlsec.ErrIDNotFound},
		{"DataReference only", `<r ` + resolveNS + `>` + target(``) + resolveEK(``, `<xenc:ReferenceList><xenc:DataReference URI="#ek"/></xenc:ReferenceList>`) + `</r>`, xmlsec.ErrIDNotFound},
		{"two RetrievalMethods apart", `<r ` + resolveNS + `>` + target(rm+`<ds:RetrievalMethod Type="`+xenc.TypeEncryptedKey+`" URI="#k2"/>`) +
			resolveEK(`Id="kek"`, ``) + resolveEK(`Id="k2"`, ``) + `</r>`, xmlsec.ErrAmbiguousID},
		{"second RetrievalMethod missing", `<r ` + resolveNS + `>` + target(rm+`<ds:RetrievalMethod Type="`+xenc.TypeEncryptedKey+`" URI="#k2"/>`) + resolveEK(`Id="kek"`, ``) + `</r>`, xmlsec.ErrIDNotFound},
		{"RetrievalMethod beside KeyName", `<r ` + resolveNS + `>` + target(rm+`<ds:KeyName>k</ds:KeyName>`) + resolveEK(`Id="kek"`, ``) + `</r>`, xmlsec.ErrUnsupportedKeyInfo},
	} {
		t.Run(c.name, func(t *testing.T) {
			ek, err := xenc.FindEncryptedKey(firstNamed(covParse(t, c.doc), "EncryptedKey"))
			if !errors.Is(err, c.want) || ek != nil {
				t.Fatalf("got %v, %v; want %v", ek, err, c.want)
			}
		})
	}
}

const dkNS = ` xmlns:xenc11="` + xmlsec.NSXEnc11 + `"`

// resolveDK is an xenc11:DerivedKey with the given attributes and trailing
// children.
func resolveDK(attrs, rest string) string {
	return `<xenc11:DerivedKey` + dkNS + ` ` + attrs + `><xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationConcatKDF + `"/>` + rest + `</xenc11:DerivedKey>`
}

// Sections 3.5.2 and 3.6: a DerivedKey in the KeyInfo, by RetrievalMethod,
// by DerivedKeyName, or by the ReferenceList inside it.
func TestFindDerivedKey(t *testing.T) {
	rm := `<ds:RetrievalMethod Type="` + xenc.TypeDerivedKey + `" URI="#dk"/>`
	for _, c := range []struct {
		name, doc, from string
	}{
		{"inline", `<r ` + resolveNS + `>` + resolveDK(`Id="decoy"`, ``) + resolveED(``, resolveDK(`Id="want"`, ``)) + `</r>`, "EncryptedData"},
		{"RetrievalMethod", `<r ` + resolveNS + `>` + resolveDK(`Id="dk" Recipient="want"`, ``) + resolveED(``, rm) + `</r>`, "EncryptedData"},
		{"RetrievalMethod of the xenc11 Type", `<r ` + resolveNS + `>` + resolveDK(`Id="dk" Recipient="want"`, ``) +
			resolveED(``, `<ds:RetrievalMethod Type="http://www.w3.org/2009/xmlenc11#DerivedKey" URI="#dk"/>`) + `</r>`, "EncryptedData"},
		{"two RetrievalMethods to one", `<r ` + resolveNS + `>` + resolveDK(`Id="dk" Recipient="want"`, ``) + resolveED(``, rm+rm) + `</r>`, "EncryptedData"},
		{"KeyName", `<r ` + resolveNS + `>` + resolveDK(`Id="n1"`, `<xenc11:DerivedKeyName>other</xenc11:DerivedKeyName>`) +
			resolveDK(`Id="want"`, `<xenc11:DerivedKeyName>dk</xenc11:DerivedKeyName>`) + resolveED(``, `<ds:KeyName>dk</ds:KeyName>`) + `</r>`, "EncryptedData"},
		{"DataReference", `<r ` + resolveNS + `>` + resolveDK(`Id="want"`, `<xenc:ReferenceList><xenc:DataReference URI="#ed"/></xenc:ReferenceList>`) +
			resolveED(`Id="ed"`, `-`) + `</r>`, "EncryptedData"},
		{"KeyReference", `<r ` + resolveNS + `>` + resolveDK(`Id="want"`, `<xenc:ReferenceList><xenc:KeyReference URI="#ek"/></xenc:ReferenceList>`) +
			resolveEK(`Id="ek"`, ``) + `</r>`, "EncryptedKey"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dk, err := xenc.FindDerivedKey(firstNamed(covParse(t, c.doc), c.from))
			if err != nil {
				t.Fatal(err)
			}
			if dk.AttrValue("Id") != "want" && dk.AttrValue("Recipient") != "want" {
				t.Fatalf("found %v", dk.Attrs)
			}
		})
	}
	for _, c := range []struct {
		name, doc, from string
		want            error
	}{
		{"not EncryptedData or EncryptedKey", `<r ` + resolveNS + `>` + resolveDK(``, ``) + `</r>`, "DerivedKey", xmlsec.ErrMalformed},
		{"EncryptedKey in KeyInfo", `<r ` + resolveNS + `>` + resolveED(``, resolveEK(``, ``)) + `</r>`, "EncryptedData", xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod of Type EncryptedKey", `<r ` + resolveNS + `>` + resolveDK(`Id="dk"`, ``) +
			resolveED(``, `<ds:RetrievalMethod Type="`+xenc.TypeEncryptedKey+`" URI="#dk"/>`) + `</r>`, "EncryptedData", xmlsec.ErrUnsupportedKeyInfo},
		{"other xenc11 Type", `<r ` + resolveNS + `>` + resolveDK(`Id="dk"`, ``) +
			resolveED(``, `<ds:RetrievalMethod Type="http://www.w3.org/2009/xmlenc11#EncryptedKey" URI="#dk"/>`) + `</r>`, "EncryptedData", xmlsec.ErrUnsupportedKeyInfo},
		{"RetrievalMethod to an EncryptedKey", `<r ` + resolveNS + `>` + resolveEK(`Id="dk"`, ``) + resolveED(``, rm) + `</r>`, "EncryptedData", xmlsec.ErrMalformed},
		{"two RetrievalMethods apart", `<r ` + resolveNS + `>` + resolveDK(`Id="dk"`, ``) + resolveDK(`Id="d2"`, ``) +
			resolveED(``, rm+`<ds:RetrievalMethod Type="`+xenc.TypeDerivedKey+`" URI="#d2"/>`) + `</r>`, "EncryptedData", xmlsec.ErrAmbiguousID},
		{"DerivedKeyName twice", `<r ` + resolveNS + `>` + resolveDK(``, `<xenc11:DerivedKeyName>dk</xenc11:DerivedKeyName>`) +
			resolveDK(``, `<xenc11:DerivedKeyName>dk</xenc11:DerivedKeyName>`) + resolveED(``, `<ds:KeyName>dk</ds:KeyName>`) + `</r>`, "EncryptedData", xmlsec.ErrAmbiguousID},
		{"KeyReference for data", `<r ` + resolveNS + `>` + resolveDK(``, `<xenc:ReferenceList><xenc:KeyReference URI="#ed"/></xenc:ReferenceList>`) +
			resolveED(`Id="ed"`, `-`) + `</r>`, "EncryptedData", xmlsec.ErrIDNotFound},
		{"EncryptedKey with no KeyInfo or Id", `<r ` + resolveNS + `>` + resolveEK(``, ``) + `</r>`, "EncryptedKey", xmlsec.ErrUnsupportedKeyInfo},
		// A KeyInfo after the CipherData is out of schema order, and not read.
		{"KeyInfo out of place", `<r ` + resolveNS + `>` + resolveEK(``, `<ds:KeyInfo>`+resolveDK(``, ``)+`</ds:KeyInfo>`) + `</r>`, "EncryptedKey", xmlsec.ErrUnsupportedKeyInfo},
	} {
		t.Run(c.name, func(t *testing.T) {
			dk, err := xenc.FindDerivedKey(firstNamed(covParse(t, c.doc), c.from))
			if !errors.Is(err, c.want) || dk != nil {
				t.Fatalf("got %v, %v; want %v", dk, err, c.want)
			}
		})
	}
}
