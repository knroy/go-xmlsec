package wss

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func ekDoc(t *testing.T, cipherData string) *xdm.Node {
	t.Helper()
	return xmltree.DocumentElement(parseDoc(t, `<xenc:EncryptedKey xmlns:xenc="`+xmlsec.NSXEnc+`" Id="ek-1">`+
		`<xenc:EncryptionMethod Algorithm="`+xmlsec.KeyTransportRSAOAEP+`"/>`+cipherData+`</xenc:EncryptedKey>`))
}

// The two EncryptedKey references of SOAP Message Security 1.1.1 section
// 7.7, as the Basic Security Profile requires them (R3069, R3072, R3070,
// R3071, R3059).
func TestEncryptedKeyReferences(t *testing.T) {
	str := NewEncryptedKeyReference("ek-1")
	b, err := c14n.Bytes(str, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	want := `<wsse:SecurityTokenReference xmlns:wsse="` + xmlsec.NSWSSE + `" xmlns:wsse11="` + xmlsec.NSWSSE11 + `" wsse11:TokenType="` +
		valueTypeEncryptedKey + `"><wsse:Reference URI="#ek-1" ValueType="` + valueTypeEncryptedKey + `"></wsse:Reference></wsse:SecurityTokenReference>`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if NewEncryptedKeyReference("") != nil {
		t.Fatal("empty ID accepted")
	}
	if err := CheckSecurityTokenReference(str); err != nil {
		t.Fatalf("not BSP: %v", err)
	}

	// The key identifier is the SHA-1 of the CipherValue octets.
	ek := ekDoc(t, `<xenc:CipherData><xenc:CipherValue>AQID BA==</xenc:CipherValue></xenc:CipherData>`)
	ki, err := NewEncryptedKeySHA1Reference(ek)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSecurityTokenReference(ki); err != nil {
		t.Fatalf("not BSP: %v", err)
	}
	if got := ki.ChildElements()[0].StringValue(); got != base64.StdEncoding.EncodeToString(sha1Of([]byte{1, 2, 3, 4})) {
		t.Fatalf("identifier %s", got)
	}
	if !MatchEncryptedKeySHA1(ki, ek) {
		t.Fatal("does not match its own EncryptedKey")
	}
	other := ekDoc(t, `<xenc:CipherData><xenc:CipherValue>AQID</xenc:CipherValue></xenc:CipherData>`)
	if MatchEncryptedKeySHA1(ki, other) {
		t.Fatal("matches another EncryptedKey")
	}

	// Only the one form matches.
	kiXML := func(attrs, value string) *xdm.Node {
		return xmltree.DocumentElement(parseDoc(t, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsse11="`+xmlsec.NSWSSE11+`"`+
			attrs+`><wsse:KeyIdentifier ValueType="`+valueTypeEncryptedKeySHA1+`">`+value+`</wsse:KeyIdentifier></wsse:SecurityTokenReference>`))
	}
	id := base64.StdEncoding.EncodeToString(sha1Of([]byte{1, 2, 3, 4}))
	for name, c := range map[string]struct {
		str  *xdm.Node
		want bool
	}{
		"no TokenType, no EncodingType": {kiXML(``, id), true},
		"other TokenType":               {kiXML(` wsse11:TokenType="urn:x"`, id), false},
		"not base64":                    {kiXML(``, "!!"), false},
		"direct reference":              {str, false},
		"not a reference":               {ek, false},
		"nil":                           {nil, false},
		"hex EncodingType": {xmltree.DocumentElement(parseDoc(t, strings.Replace(
			`<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`"><wsse:KeyIdentifier ValueType="`+valueTypeEncryptedKeySHA1+`">`+id+
				`</wsse:KeyIdentifier></wsse:SecurityTokenReference>`, `<wsse:KeyIdentifier `, `<wsse:KeyIdentifier EncodingType="urn:hex" `, 1))), false},
	} {
		if got := MatchEncryptedKeySHA1(c.str, ek); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if MatchEncryptedKeySHA1(ki, nil) {
		t.Error("nil EncryptedKey matched")
	}

	for name, ek := range map[string]*xdm.Node{
		"not an EncryptedKey": ekDoc(t, ``).ChildElements()[0],
		"no CipherData":       ekDoc(t, ``),
		"CipherReference":     ekDoc(t, `<xenc:CipherData><xenc:CipherReference URI="#x"/></xenc:CipherData>`),
		"not base64":          ekDoc(t, `<xenc:CipherData><xenc:CipherValue>!!</xenc:CipherValue></xenc:CipherData>`),
		"empty":               ekDoc(t, `<xenc:CipherData><xenc:CipherValue/></xenc:CipherData>`),
	} {
		if _, err := NewEncryptedKeySHA1Reference(ek); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
