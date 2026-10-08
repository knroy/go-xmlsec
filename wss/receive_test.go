package wss

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// FindHeader returns the one wsse:Security header for a recipient, nil when
// there is none, and refuses two for the same one (BSP R3206, R3210); for
// SOAP 1.2 the ultimateReceiver role is the same recipient as no role.
func TestFindHeader(t *testing.T) {
	sec := func(attrs string) string { return `<wsse:Security` + attrs + `/>` }
	env := func(ns, hdr string) string {
		return `<e:Envelope xmlns:e="` + ns + `" xmlns:wsse="` + xmlsec.NSWSSE + `">` + hdr + `<e:Body/></e:Envelope>`
	}
	h := func(kids ...string) string {
		s := `<e:Header>`
		for _, k := range kids {
			s += k
		}
		return s + `</e:Header>`
	}
	for name, c := range map[string]struct {
		ns, doc, actor string
		found          bool
		want           error
	}{
		"one":                       {xmlsec.NSSOAP11, h(sec(``)), "", true, nil},
		"one for an actor":          {xmlsec.NSSOAP11, h(sec(``), sec(` e:actor="urn:a"`)), "urn:a", true, nil},
		"none for the actor":        {xmlsec.NSSOAP11, h(sec(` e:actor="urn:a"`)), "", false, nil},
		"no SOAP Header":            {xmlsec.NSSOAP11, ``, "", false, nil},
		"R3206 two without":         {xmlsec.NSSOAP11, h(sec(``), sec(``)), "", false, xmlsec.ErrMalformed},
		"R3210 two for an actor":    {xmlsec.NSSOAP11, h(sec(` e:actor="urn:a"`), sec(` e:actor="urn:a"`)), "urn:a", false, xmlsec.ErrMalformed},
		"SOAP 1.2 ultimateReceiver": {xmlsec.NSSOAP12, h(sec(``), sec(` e:role="`+roleUltimateReceiver+`"`)), "", false, xmlsec.ErrMalformed},
		"SOAP 1.2 role":             {xmlsec.NSSOAP12, h(sec(` e:role="urn:r"`)), "urn:r", true, nil},
	} {
		got, err := FindHeader(parseDoc(t, env(c.ns, c.doc)), c.ns, c.actor)
		if !errors.Is(err, c.want) || (got != nil) != c.found {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
	if _, err := FindHeader(parseDoc(t, env11), "urn:x", ""); err == nil {
		t.Error("unknown SOAP namespace accepted")
	}
	if _, err := FindHeader(parseDoc(t, env11), xmlsec.NSSOAP12, ""); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("wrong envelope: %v", err)
	}
	if _, err := FindHeader(nil, xmlsec.NSSOAP12, ""); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("nil document: %v", err)
	}
}

// FindTimestamp returns the one wsu:Timestamp of a header, nil when there is
// none, and refuses two (BSP R3227).
func TestFindTimestamp(t *testing.T) {
	ts := `<wsu:Timestamp><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>`
	sec := func(inner string) *xdm.Node {
		return xmltree.DocumentElement(parseDoc(t, `<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsu="`+xmlsec.NSWSU+`"><x/>`+inner+`</wsse:Security>`))
	}
	if got, err := FindTimestamp(sec(ts)); err != nil || got == nil {
		t.Fatalf("one: %v, %v", got, err)
	}
	if got, err := FindTimestamp(sec(``)); err != nil || got != nil {
		t.Fatalf("none: %v, %v", got, err)
	}
	if _, err := FindTimestamp(sec(ts + ts)); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("two: %v", err)
	}
	if _, err := FindTimestamp(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("nil: %v", err)
	}
}

// CheckUniqueIDs refuses a document in which any ID value repeats across
// wsu:Id, xml:id and the extra attributes, and counts nothing else (BSP
// R3204).
func TestCheckUniqueIDs(t *testing.T) {
	doc := func(inner string) *xdm.Node {
		return parseDoc(t, `<r xmlns:wsu="`+xmlsec.NSWSU+`">`+inner+`</r>`)
	}
	samlID := xdm.QName{Local: "ID"}
	for name, c := range map[string]struct {
		inner string
		extra []xdm.QName
		want  error
	}{
		"unique":                    {`<a wsu:Id="a"/><b xml:id="b"/><c ID="a"/>`, nil, nil},
		"wsu:Id twice":              {`<a wsu:Id="x"/><b wsu:Id="x"/>`, nil, xmlsec.ErrAmbiguousID},
		"wsu:Id and xml:id":         {`<a wsu:Id="x"/><b xml:id="x"/>`, nil, xmlsec.ErrAmbiguousID},
		"both on one element":       {`<a wsu:Id="x" xml:id="x"/>`, nil, xmlsec.ErrAmbiguousID},
		"extra attribute":           {`<a wsu:Id="x"/><c ID="x"/>`, []xdm.QName{samlID}, xmlsec.ErrAmbiguousID},
		"unnamed attribute ignored": {`<c ID="x"/><d ID="x"/>`, nil, nil},
	} {
		if err := CheckUniqueIDs(doc(c.inner), c.extra...); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckUniqueIDs(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("nil: %v", err)
	}
}

// CheckSecurityTokenReference applies the Basic Security Profile's syntax
// rules for a reference, whatever it names.
func TestCheckSecurityTokenReference(t *testing.T) {
	const (
		b64 = ` EncodingType="` + xmlsec.BSTEncodingBase64 + `"`
		ski = ` ValueType="` + valueTypeSKI + `"`
		ekv = ` ValueType="` + valueTypeEncryptedKeySHA1 + `"`
	)
	tt := func(v string) string { return ` wsse11:TokenType="` + v + `"` }
	str := func(attrs, inner string) *xdm.Node {
		return xmltree.DocumentElement(parseDoc(t, `<wsse:SecurityTokenReference xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsse11="`+
			xmlsec.NSWSSE11+`" xmlns:ds="`+xmlsec.NSDSig+`"`+attrs+`>`+inner+`</wsse:SecurityTokenReference>`))
	}
	ki := func(attrs string) string { return `<wsse:KeyIdentifier` + attrs + `>AAAA</wsse:KeyIdentifier>` }
	for name, c := range map[string]struct {
		attrs, inner string
		ok           bool
	}{
		"direct reference":             {``, `<wsse:Reference URI="#a"/>`, true},
		"R3062 no URI":                 {``, `<wsse:Reference/>`, false},
		"embedded":                     {``, `<wsse:Embedded><t/></wsse:Embedded>`, true},
		"R3060 empty Embedded":         {``, `<wsse:Embedded/>`, false},
		"SKI":                          {``, ki(ski + b64), true},
		"SKI, X509v3 TokenType":        {tt(xmlsec.BSTValueTypeX509v3), ki(ski + b64), true},
		"SKI, PKIPath TokenType":       {tt(xmlsec.BSTValueTypeX509PKIPath), ki(ski + b64), false},
		"ThumbprintSHA1":               {``, ki(` ValueType="` + valueTypeThumbprintSHA1 + `"` + b64), true},
		"R3054 no ValueType":           {``, ki(b64), false},
		"R3070 no EncodingType":        {``, ki(ski), false},
		"R3071 other EncodingType":     {``, ki(ski + ` EncodingType="urn:hex"`), false},
		"EncryptedKeySHA1":             {tt(valueTypeEncryptedKey), ki(ekv + b64), true},
		"R3069 EncryptedKeySHA1 alone": {``, ki(ekv + b64), false},
		"SAML without EncodingType":    {``, ki(` ValueType="` + valueTypeSAML2AssertionID + `"`), true},
		"R6604 SAML with EncodingType": {``, ki(` ValueType="` + valueTypeSAMLAssertionID + `"` + b64), false},
		"EncryptedKey reference":       {tt(valueTypeEncryptedKey), `<wsse:Reference URI="#ek" ValueType="` + valueTypeEncryptedKey + `"/>`, true},
		"R3069 EncryptedKey reference": {``, `<wsse:Reference URI="#ek" ValueType="` + valueTypeEncryptedKey + `"/>`, false},
		"issuer serial":                {tt(xmlsec.BSTValueTypePKCS7), `<ds:X509Data/>`, true},
		"issuer serial, EncryptedKey":  {tt(valueTypeEncryptedKey), `<ds:X509Data/>`, false},
		"R3027 KeyName":                {``, `<ds:KeyName>k</ds:KeyName>`, false},
		"R3061 two references":         {``, `<wsse:Reference URI="#a"/><wsse:Reference URI="#b"/>`, false},
		"R3061 no reference":           {``, ``, false},
	} {
		err := CheckSecurityTokenReference(str(c.attrs, c.inner))
		if c.ok != (err == nil) || err != nil && !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckSecurityTokenReference(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("nil: %v", err)
	}
	// A key identifier of a profile this library does not read is
	// unsupported, not a breach of R3063.
	for name, vt := range map[string]string{
		"unknown":          "urn:x",
		"Kerberos (R6906)": "http://docs.oasis-open.org/wss/oasis-wss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1",
	} {
		err := CheckSecurityTokenReference(str(``, ki(` ValueType="`+vt+`"`+b64)))
		if !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) || errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
