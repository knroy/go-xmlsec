package dsig_test

import (
	"crypto/x509"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// StrictBSP applies the Basic Security Profile's rules for a signature
// before any cryptographic work: a message this library builds with the
// conforming recipe passes, and each altered one is refused for the rule it
// breaks, not as an invalid signature, although none is re-signed.
func TestStrictBSP(t *testing.T) {
	signed, msgID, _ := signAS4(t, newKey(t, rsaKey))
	opts := as4Allow
	opts.Attachments = attachments(t, "payload")
	opts.StrictBSP = true
	verify := func(s string) error {
		doc := parse(t, []byte(s))
		_, err := dsig.Verify(doc, findSignature(doc), opts)
		return err
	}
	if err := verify(string(signed)); err != nil {
		t.Fatalf("conforming message: %v", err)
	}

	exc := `<ds:Transform Algorithm="` + string(c14n.Exclusive10) + `"></ds:Transform>`
	firstTransforms := regexp.MustCompile(`<ds:Transforms>.*?</ds:Transforms>`)
	for name, c := range map[string]struct {
		edit func(string) string
		want error
	}{
		"R5404 inclusive SignedInfo": {func(s string) string {
			return strings.Replace(s, `<ds:CanonicalizationMethod Algorithm="`+string(c14n.Exclusive10), `<ds:CanonicalizationMethod Algorithm="`+string(c14n.Inclusive10), 1)
		}, xmlsec.ErrAlgorithmNotAllowed},
		"R5401 HMACOutputLength": {func(s string) string {
			return strings.Replace(s, `"></ds:SignatureMethod>`, `"><ds:HMACOutputLength>256</ds:HMACOutputLength></ds:SignatureMethod>`, 1)
		}, xmlsec.ErrMalformed},
		"R5402 two KeyInfo children": {func(s string) string {
			return strings.Replace(s, `<ds:KeyInfo>`, `<ds:KeyInfo><ds:KeyName>k</ds:KeyName>`, 1)
		}, xmlsec.ErrMalformed},
		"R5417 no token reference": {func(s string) string {
			return strings.ReplaceAll(s, `wsse:SecurityTokenReference`, `wsse:Other`)
		}, xmlsec.ErrMalformed},
		"R3061 two token references": {func(s string) string {
			return strings.Replace(s, `</wsse:SecurityTokenReference>`, `<wsse:Reference URI="#x"></wsse:Reference></wsse:SecurityTokenReference>`, 1)
		}, xmlsec.ErrMalformed},
		"R5403 Manifest": {func(s string) string {
			return strings.Replace(s, `</ds:KeyInfo>`, `</ds:KeyInfo><ds:Object><ds:Manifest></ds:Manifest></ds:Object>`, 1)
		}, xmlsec.ErrMalformed},
		"R5440 EncryptedData": {func(s string) string {
			return strings.Replace(s, `</ds:KeyInfo>`, `</ds:KeyInfo><ds:Object><xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`"></xenc:EncryptedData></ds:Object>`, 1)
		}, xmlsec.ErrMalformed},
		"R5416 no Transforms": {func(s string) string {
			return firstTransforms.ReplaceAllStringFunc(s, func(m string) string {
				if strings.Contains(m, "Attachment") {
					return m
				}
				return ""
			})
		}, xmlsec.ErrMalformed},
		"R5423 inclusive transform": {func(s string) string {
			return strings.Replace(s, exc, `<ds:Transform Algorithm="`+string(c14n.Inclusive10)+`"></ds:Transform>`, 1)
		}, xmlsec.ErrAlgorithmNotAllowed},
		"R5412 ends with enveloped-signature": {func(s string) string {
			return strings.Replace(s, exc, exc+`<ds:Transform Algorithm="`+xmlsec.TransformEnvelopedSignature+`"></ds:Transform>`, 1)
		}, xmlsec.ErrAlgorithmNotAllowed},
		"R6101 attachment without an SwA transform": {func(s string) string {
			return strings.Replace(s, xmlsec.TransformAttachmentContentSignature, string(c14n.Exclusive10), 1)
		}, xmlsec.ErrMalformed},
		"R3102 enveloping": {func(s string) string {
			s = strings.Replace(s, `</ds:KeyInfo>`, `</ds:KeyInfo><ds:Object><o xmlns:wsu="`+xmlsec.NSWSU+`" wsu:Id="obj"></o></ds:Object>`, 1)
			return strings.Replace(s, `URI="#`+msgID+`"`, `URI="#obj"`, 1)
		}, xmlsec.ErrMalformed},
		"reference to nothing": {func(s string) string {
			return strings.Replace(s, `URI="#`+msgID+`"`, `URI="#nothing"`, 1)
		}, xmlsec.ErrIDNotFound},
		"unsupported XPointer": {func(s string) string {
			return strings.Replace(s, `URI="#`+msgID+`"`, `URI="#xpointer(//*)"`, 1)
		}, xmlsec.ErrMalformed},
		// The whole document is not inside the signature: the profile's
		// rules pass, and only the unsigned change fails.
		"whole document": {func(s string) string {
			return strings.Replace(s, `URI="#`+msgID+`"`, `URI=""`, 1)
		}, xmlsec.ErrSignatureInvalid},
	} {
		got := c.edit(string(signed))
		if got == string(signed) {
			t.Fatalf("%s: no change", name)
		}
		if err := verify(got); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// signKeyInfoElement signs the envelope's Body with ds:KeyInfo holding el.
func signKeyInfoElement(t *testing.T, key xmlsec.KeyProvider, el *xdm.Node) ([]byte, error) {
	t.Helper()
	doc := parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]
	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", false)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256}},
		KeyInfo:                   dsig.KeyInfoSecurityTokenReference,
		KeyInfoElement:            el,
	})
	if err != nil {
		return nil, err
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	return serialize(t, doc), nil
}

// SignOptions.KeyInfoElement puts a key identifier or issuer-serial
// reference in ds:KeyInfo, for a certificate the message does not carry
// (BSP R5417, R5209). The receiver resolves it with ResolveSecurityToken, or
// pins the certificate; under StrictSecurityTokenReference or StrictBSP a
// pinned certificate must be the one the reference names.
func TestKeyInfoElement(t *testing.T) {
	key := newKey(t, rsaKey)
	// Another key, and for issuer-serial another serial number: newKey
	// gives every certificate the same issuer and serial.
	ecCert := newKey(t, covECKey).Certificate
	ecCert.SerialNumber = big.NewInt(2)
	for _, mk := range []func(*x509.Certificate) (*xdm.Node, error){wss.NewKeyIdentifierReference, wss.NewIssuerSerialReference} {
		str, err := mk(key.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signKeyInfoElement(t, key, str)
		if err != nil {
			t.Fatal(err)
		}
		resolve := func(str *xdm.Node) (*x509.Certificate, error) {
			if !wss.MatchSecurityTokenReference(str, key.Certificate) {
				return nil, errors.New("unknown")
			}
			return key.Certificate, nil
		}
		for name, c := range map[string]struct {
			opts dsig.VerifyOptions
			want error
		}{
			"resolved":                    {dsig.VerifyOptions{ResolveSecurityToken: resolve}, nil},
			"resolved, strict":            {dsig.VerifyOptions{ResolveSecurityToken: resolve, StrictSecurityTokenReference: true}, nil},
			"unresolved":                  {dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
			"resolver fails":              {dsig.VerifyOptions{ResolveSecurityToken: func(*xdm.Node) (*x509.Certificate, error) { return nil, errors.New("x") }}, xmlsec.ErrSecurityTokenUnavailable},
			"pinned, strict":              {dsig.VerifyOptions{Certificate: key.Certificate, StrictBSP: true}, nil},
			"pinned other, strict":        {dsig.VerifyOptions{Certificate: ecCert, StrictSecurityTokenReference: true}, xmlsec.ErrUnsupportedKeyInfo},
			"pinned other, lenient":       {dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrUnsupportedAlgorithm},
			"pinned, resolver not called": {dsig.VerifyOptions{Certificate: key.Certificate, ResolveSecurityToken: func(*xdm.Node) (*x509.Certificate, error) { panic("called") }}, nil},
		} {
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, findSignature(doc), c.opts)
			if !errors.Is(err, c.want) || err == nil && !cov.Certificate.Equal(key.Certificate) {
				t.Errorf("%s: %v", name, err)
			}
			if name == "resolved" && cov.KeyInfoForm != dsig.KeyInfoSecurityTokenReference {
				t.Errorf("form %v", cov.KeyInfoForm)
			}
		}
	}

	// Strict: the reference itself must follow the profile (R3070).
	str, _ := wss.NewKeyIdentifierReference(key.Certificate)
	signed, err := signKeyInfoElement(t, key, str)
	if err != nil {
		t.Fatal(err)
	}
	loose := parse(t, []byte(strings.Replace(string(signed), ` EncodingType="`+xmlsec.BSTEncodingBase64+`"`, "", 1)))
	if _, err := dsig.Verify(loose, findSignature(loose), dsig.VerifyOptions{StrictSecurityTokenReference: true,
		ResolveSecurityToken: func(*xdm.Node) (*x509.Certificate, error) { return key.Certificate, nil }}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("no EncodingType, strict: %v", err)
	}

	// An EncryptedKey reference is placed as given.
	if signed, err := signKeyInfoElement(t, key, wss.NewEncryptedKeyReference("ek-1")); err != nil || !strings.Contains(string(signed), `URI="#ek-1"`) {
		t.Fatalf("EncryptedKey reference: %v", err)
	}

	// A reference naming nothing by a property is placed as given too.
	empty := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "SecurityTokenReference")
	empty.AddNamespace("wsse", xmlsec.NSWSSE)
	if _, err := signKeyInfoElement(t, key, empty); err != nil {
		t.Fatalf("empty reference: %v", err)
	}

	// Refused: another certificate, an attached element, not a reference.
	other, _ := wss.NewKeyIdentifierReference(ecCert)
	if _, err := signKeyInfoElement(t, key, other); err == nil {
		t.Error("another certificate accepted")
	}
	attached, _ := wss.NewKeyIdentifierReference(key.Certificate)
	xmltree.Element(nil, "p", "urn:p", "p").AppendChild(attached)
	if _, err := signKeyInfoElement(t, key, attached); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("attached: %v", err)
	}
	if _, err := signKeyInfoElement(t, key, xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("KeyName: %v", err)
	}
}
