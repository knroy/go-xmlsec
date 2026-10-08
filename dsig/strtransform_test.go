package dsig_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

var strTransform = []dsig.TransformSpec{{Algorithm: xmlsec.TransformSTR}}

// signSTR builds the envelope with a binary security token for key's
// certificate and a wsse:SecurityTokenReference after it in the header,
// made by mkSTR, and signs the Body and, through the STR Dereference
// Transform, the reference's token. It returns the signed message.
func signSTR(t *testing.T, key xmlsec.KeyProvider, mkSTR func(doc *xdm.Node, tokID string) *xdm.Node, edit func(*dsig.SignOptions)) []byte {
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
	tokID, err := hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	str := mkSTR(doc, tokID)
	if err := hdr.Append(str); err != nil {
		t.Fatal(err)
	}
	strID, err := wss.AssignID(doc, str)
	if err != nil {
		t.Fatal(err)
	}
	opts := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + strID, Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo: dsig.KeyInfoX509Data,
	}
	if edit != nil {
		edit(&opts)
	}
	if !c14n.Algorithm(opts.CanonicalizationAlgorithm).Exclusive() {
		opts.Parent = hdr.Element()
	}
	sig, err := dsig.Sign(doc, key, opts)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Parent == nil {
		if err := hdr.Append(sig); err != nil {
			t.Fatal(err)
		}
	}
	return serialize(t, doc)
}

func directSTR(t *testing.T) func(*xdm.Node, string) *xdm.Node {
	return func(doc *xdm.Node, tokID string) *xdm.Node {
		str, err := wss.NewSecurityTokenReference(doc, tokID, "")
		if err != nil {
			t.Fatal(err)
		}
		return str
	}
}

func keyIdentifierSTR(t *testing.T, cert *x509.Certificate) func(*xdm.Node, string) *xdm.Node {
	return func(*xdm.Node, string) *xdm.Node {
		str, err := wss.NewKeyIdentifierReference(cert)
		if err != nil {
			t.Fatal(err)
		}
		return str
	}
}

func verifySTR(t *testing.T, signed []byte, opts dsig.VerifyOptions) (*dsig.Coverage, error) {
	t.Helper()
	doc := parse(t, signed)
	return dsig.Verify(doc, findSignature(doc), opts)
}

// The STR Dereference Transform (SOAP Message Security 1.1.1 section 8.3)
// digests the token a reference names, not the reference: Coverage reports
// the token in SignedTokens and not the reference, a change to the token
// breaks the digest, and a change to the reference that names the same
// token does not.
func TestSTRTransformDirectReference(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := signSTR(t, key, directSTR(t), nil)
	// The PrefixList states the default namespace the transform renders.
	if !strings.Contains(string(signed), `<wsse:TransformationParameters><ds:CanonicalizationMethod Algorithm="`+string(c14n.Exclusive10)+
		`"><ec:InclusiveNamespaces xmlns:ec="`+xmlsec.NSExcC14N+`" PrefixList="#default"></ec:InclusiveNamespaces></ds:CanonicalizationMethod></wsse:TransformationParameters>`) {
		t.Fatalf("transform parameters not emitted:\n%s", signed)
	}
	cov, err := verifySTR(t, signed, dsig.VerifyOptions{Certificate: key.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.SignedTokens) != 1 || !cov.SignedTokens[0].IsElement(xmlsec.NSWSSE, "BinarySecurityToken") || len(cov.SignedElements) != 1 {
		t.Fatalf("coverage %+v", cov)
	}
	if got := cov.References[1].Transforms; len(got) != 1 || got[0].Algorithm != xmlsec.TransformSTR {
		t.Fatalf("reference transforms %+v", got)
	}

	// The reference is not covered: a TokenType added to it verifies.
	loose := strings.Replace(string(signed), `<wsse:SecurityTokenReference `,
		`<wsse:SecurityTokenReference xmlns:wsse11="`+xmlsec.NSWSSE11+`" wsse11:TokenType="`+xmlsec.BSTValueTypeX509v3+`" `, 1)
	if _, err := verifySTR(t, []byte(loose), dsig.VerifyOptions{Certificate: key.Certificate}); err != nil {
		t.Fatalf("reference changed: %v", err)
	}
	// The token is: an attribute added to it does not.
	swapped := strings.Replace(string(signed), `<wsse:BinarySecurityToken `, `<wsse:BinarySecurityToken a="1" `, 1)
	if _, err := verifySTR(t, []byte(swapped), dsig.VerifyOptions{Certificate: key.Certificate}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("token changed: %v", err)
	}
	// A reference that names nothing cannot be dereferenced (section 8.3:
	// the transform "MUST signal a failure").
	gone := strings.Replace(string(signed), `URI="#`, `URI="#gone-`, 1)
	if _, err := verifySTR(t, []byte(gone), dsig.VerifyOptions{Certificate: key.Certificate}); !errors.Is(err, xmlsec.ErrSecurityTokenUnavailable) {
		t.Fatalf("token missing: %v", err)
	}
	// Exclusive C14N must be allowed for the transform's serialization.
	inc := string(c14n.Inclusive10)
	signed = signSTR(t, key, directSTR(t), func(o *dsig.SignOptions) {
		o.CanonicalizationAlgorithm = inc
		o.References[0].Transforms = []dsig.TransformSpec{{Algorithm: inc}}
	})
	opts := dsig.VerifyOptions{Certificate: key.Certificate, AllowedCanonicalizationAlgorithms: []string{inc}}
	if _, err := verifySTR(t, signed, opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("Exclusive C14N not allowed: %v", err)
	}
	opts.AllowedCanonicalizationAlgorithms = append(opts.AllowedCanonicalizationAlgorithms, string(c14n.Exclusive10))
	if _, err := verifySTR(t, signed, opts); err != nil {
		t.Fatalf("Exclusive C14N allowed: %v", err)
	}
}

// A key identifier names a certificate the message does not carry. Section
// 8.3 digests an X509v3 wsse:BinarySecurityToken built from it, with the
// reference's prefix, no EncodingType and no white space in the content;
// the caller's ResolveSecurityToken supplies the certificate, and without
// it the transform fails.
func TestSTRTransformKeyIdentifier(t *testing.T) {
	key := newKey(t, rsaKey)
	resolve := func(str *xdm.Node) (*x509.Certificate, error) {
		if !wss.MatchSecurityTokenReference(str, key.Certificate) {
			return nil, errors.New("unknown")
		}
		return key.Certificate, nil
	}
	signed := signSTR(t, key, keyIdentifierSTR(t, key.Certificate), func(o *dsig.SignOptions) { o.ResolveSecurityToken = resolve })

	// The digest is that of the token section 8.3 describes, with the
	// xmlns="" it requires on the apex.
	want := sha256.Sum256([]byte(`<wsse:BinarySecurityToken xmlns="" xmlns:wsse="` + xmlsec.NSWSSE + `" ValueType="` +
		xmlsec.BSTValueTypeX509v3 + `">` + base64.StdEncoding.EncodeToString(key.Certificate.Raw) + `</wsse:BinarySecurityToken>`))
	if !strings.Contains(string(signed), base64.StdEncoding.EncodeToString(want[:])) {
		t.Fatalf("digest of the built token not found:\n%s", signed)
	}

	cov, err := verifySTR(t, signed, dsig.VerifyOptions{Certificate: key.Certificate, ResolveSecurityToken: resolve})
	if err != nil {
		t.Fatal(err)
	}
	if tok := cov.SignedTokens[0]; tok.Parent != nil || tok.AttrValue("ValueType") != xmlsec.BSTValueTypeX509v3 || tok.Attr("", "EncodingType") != nil {
		t.Fatalf("built token %+v", tok)
	}

	// An unprefixed reference gets the wsse prefix, as in WSS4J.
	signed = signSTR(t, key, func(doc *xdm.Node, tokID string) *xdm.Node {
		str := keyIdentifierSTR(t, key.Certificate)(doc, tokID)
		str.Name.Prefix, str.ChildElements()[0].Name.Prefix = "", ""
		str.AddNamespace("", xmlsec.NSWSSE)
		return str
	}, func(o *dsig.SignOptions) { o.ResolveSecurityToken = resolve })
	if !strings.Contains(string(signed), base64.StdEncoding.EncodeToString(want[:])) {
		t.Fatalf("unprefixed reference: digest of the built token not found:\n%s", signed)
	}

	for name, c := range map[string]func(*xdm.Node) (*x509.Certificate, error){
		"no resolver":    nil,
		"resolver fails": func(*xdm.Node) (*x509.Certificate, error) { return nil, errors.New("unknown") },
		"no certificate": func(*xdm.Node) (*x509.Certificate, error) { return nil, nil },
	} {
		if _, err := verifySTR(t, signed, dsig.VerifyOptions{Certificate: key.Certificate, ResolveSecurityToken: c}); !errors.Is(err, xmlsec.ErrSecurityTokenUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A wsse:Embedded token (section 7.4) is dereferenced where it stands.
func TestSTRTransformEmbedded(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := signSTR(t, key, func(doc *xdm.Node, tokID string) *xdm.Node {
		tok, err := wss.FindByID(doc, tokID)
		if err != nil {
			t.Fatal(err)
		}
		str := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "SecurityTokenReference")
		str.AddNamespace("wsse", xmlsec.NSWSSE)
		emb := xmltree.Element(str, "wsse", xmlsec.NSWSSE, "Embedded")
		// Moved into the reference: the header keeps no copy.
		tok.Parent.Children = tok.Parent.Children[1:]
		tok.Parent = nil
		emb.AppendChild(tok)
		return str
	}, nil)
	cov, err := verifySTR(t, signed, dsig.VerifyOptions{Certificate: key.Certificate})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.SignedTokens[0].Parent.IsElement(xmlsec.NSWSSE, "Embedded") {
		t.Fatalf("coverage %+v", cov)
	}
}

// Sign refuses the transform anywhere but as the only transform of a
// reference by ID, and on a reference that is not to a token reference.
func TestSTRTransformSignRefusals(t *testing.T) {
	key := newKey(t, rsaKey)
	doc, tokID, bodyID := covTokenDoc(t, key)
	sign := func(uri string, ts ...dsig.TransformSpec) error {
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References:                []dsig.Reference{{URI: uri, Transforms: ts, DigestAlgorithm: xmlsec.DigestSHA256}},
		})
		return err
	}
	str := dsig.TransformSpec{Algorithm: xmlsec.TransformSTR}
	for name, err := range map[string]error{
		"with another transform": sign("#"+bodyID, str, excC14N[0]),
		"whole document":         sign("#xpointer(/)", str),
		"attachment":             sign("cid:a", str),
		"not a reference":        sign("#"+tokID, str),
	} {
		if !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key identifier without a resolver cannot be dereferenced.
	if err := signKeyIdentifierNoResolver(t, key); !errors.Is(err, xmlsec.ErrSecurityTokenUnavailable) {
		t.Fatalf("key identifier, no resolver: %v", err)
	}
}

// signKeyIdentifierNoResolver signs a key identifier reference through the
// transform without a resolver, returning Sign's error.
func signKeyIdentifierNoResolver(t *testing.T, key xmlsec.KeyProvider) error {
	doc := parse(t, []byte(envelope))
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", false)
	if err != nil {
		t.Fatal(err)
	}
	str, _ := wss.NewKeyIdentifierReference(key.Certificate)
	if err := hdr.Append(str); err != nil {
		t.Fatal(err)
	}
	id, _ := wss.AssignID(doc, str)
	_, err = dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                []dsig.Reference{{URI: "#" + id, Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256}},
	})
	return err
}

// A received STR Dereference Transform must carry exactly one
// wsse:TransformationParameters, without attributes, holding one
// ds:CanonicalizationMethod naming a canonicalization (BSP R3065; SOAP Message Security section
// 8.3: unrecognized parameters SHOULD fault), and must be the only
// transform of a reference to a wsse:SecurityTokenReference. Each altered
// signature is re-signed, so only the property under test decides.
func TestSTRTransformVerifyRefusals(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := string(signSTR(t, key, directSTR(t), func(o *dsig.SignOptions) {
		// A new slice: strTransform is shared.
		o.References[1].Transforms = []dsig.TransformSpec{{Algorithm: xmlsec.TransformSTR, InclusiveNamespacePrefixes: []string{"S"}}}
	}))
	const params = `<wsse:TransformationParameters><ds:CanonicalizationMethod Algorithm="` + string(c14n.Exclusive10) +
		`"><ec:InclusiveNamespaces xmlns:ec="` + xmlsec.NSExcC14N + `" PrefixList="S #default"></ec:InclusiveNamespaces></ds:CanonicalizationMethod></wsse:TransformationParameters>`
	if !strings.Contains(signed, params) {
		t.Fatalf("PrefixList not emitted:\n%s", signed)
	}
	if _, err := verifySTR(t, []byte(signed), dsig.VerifyOptions{Certificate: key.Certificate}); err != nil {
		t.Fatalf("with a PrefixList: %v", err)
	}
	strURI := signed[strings.LastIndex(signed, `<ds:Reference URI="#`)+len(`<ds:Reference URI="#`):]
	strURI = strURI[:strings.IndexByte(strURI, '"')]
	for name, c := range map[string]struct {
		old, new string
		want     error
	}{
		"no parameters":   {params, "", xmlsec.ErrMalformed},
		"two parameters":  {params, params + params, xmlsec.ErrMalformed},
		"attribute":       {`<wsse:TransformationParameters>`, `<wsse:TransformationParameters a="1">`, xmlsec.ErrMalformed},
		"other parameter": {params, strings.ReplaceAll(params, "CanonicalizationMethod", "DigestMethod"), xmlsec.ErrMalformed},
		"not a canonicalization": {params, `<wsse:TransformationParameters><ds:CanonicalizationMethod Algorithm="` + xmlsec.TransformBase64 +
			`"></ds:CanonicalizationMethod></wsse:TransformationParameters>`, xmlsec.ErrUnsupportedAlgorithm},
		"unknown parameter": {`<ec:InclusiveNamespaces`, `<x xmlns="urn:x"></x><ec:InclusiveNamespaces`, xmlsec.ErrMalformed},
		"not the only transform": {`</ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"></ds:DigestMethod><ds:DigestValue>` + signed[strings.LastIndex(signed, "<ds:DigestValue>")+16:strings.LastIndex(signed, "</ds:DigestValue>")],
			`</ds:Transform><ds:Transform Algorithm="` + string(c14n.Exclusive10) + `"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"></ds:DigestMethod><ds:DigestValue>` + signed[strings.LastIndex(signed, "<ds:DigestValue>")+16:strings.LastIndex(signed, "</ds:DigestValue>")], xmlsec.ErrMalformed},
		"not a reference": {`URI="#` + strURI + `"`, `URI="#` + xmltree.AttrValue(xmltree.DocumentElement(parse(t, []byte(signed))).ChildElements()[1], xmlsec.NSWSU, "Id") + `"`, xmlsec.ErrMalformed},
	} {
		got := strings.Replace(signed, c.old, c.new, 1)
		if got == signed {
			t.Fatalf("%s: no change", name)
		}
		doc := parse(t, []byte(got))
		sig := findSignature(doc)
		resignSI(t, sig, c14n.Exclusive10)
		if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A token with no canonical form fails the transform, and a wsse prefix
// bound to another namespace where the signature is computed fails Sign.
func TestSTRTransformSignFailures(t *testing.T) {
	key := newKey(t, rsaKey)
	doc := parse(t, []byte(`<r xmlns:wsu="`+xmlsec.NSWSU+`" xmlns:w="`+xmlsec.NSWSSE+`" xmlns:rel="relative">`+
		`<w:SecurityTokenReference wsu:Id="s"><w:Embedded><rel:t></rel:t></w:Embedded></w:SecurityTokenReference>`+
		`<w:SecurityTokenReference wsu:Id="ok"><w:Embedded><t></t></w:Embedded></w:SecurityTokenReference>`+
		`<p xmlns:wsse="urn:other"></p></r>`))
	sign := func(id string, parent *xdm.Node) error {
		_, err := dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References:                []dsig.Reference{{URI: "#" + id, Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256}},
			Parent:                    parent,
		})
		return err
	}
	if err := sign("s", nil); !errors.Is(err, c14n.ErrRelativeNamespaceURI) {
		t.Errorf("relative namespace: %v", err)
	}
	if err := sign("ok", xmltree.DocumentElement(doc).ChildElements()[2]); err == nil || !strings.Contains(err.Error(), "wsse") {
		t.Errorf("wsse bound elsewhere: %v", err)
	}
}

// ds:KeyInfo is built before any reference is digested, so the signature
// can sign its own ds:KeyInfo reference through the STR Dereference
// Transform, as WSS4J does, and the result passes StrictBSP: a reference
// into ds:KeyInfo is not an enveloping one.
func TestSTRTransformOverKeyInfo(t *testing.T) {
	key := newKey(t, rsaKey)
	doc, tokID, bodyID := covTokenDoc(t, key)
	str, err := wss.NewSecurityTokenReference(doc, tokID, "")
	if err != nil {
		t.Fatal(err)
	}
	strID, err := wss.AssignID(doc, str)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + bodyID, Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + strID, Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo:        dsig.KeyInfoSecurityTokenReference,
		KeyInfoElement: str,
		Parent:         xmltree.DocumentElement(doc).ChildElements()[0].ChildElements()[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{StrictBSP: true})
	if err != nil || len(cov.SignedTokens) != 1 || cov.SignedTokens[0].AttrValue("ValueType") != xmlsec.BSTValueTypeX509v3 ||
		!cov.Certificate.Equal(key.Certificate) {
		t.Fatalf("%v, %+v", err, cov)
	}
}

// samlSTRDoc is a SOAP envelope whose header carries tokens, then a
// wsse:SecurityTokenReference with wsu:Id "str" holding ki.
func samlSTRDoc(t *testing.T, tokens, ki string) *xdm.Node {
	return parse(t, []byte(`<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope"><S:Header>`+
		`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:wsu="`+xmlsec.NSWSU+`">`+tokens+
		`<wsse:SecurityTokenReference wsu:Id="str">`+ki+`</wsse:SecurityTokenReference>`+
		`</wsse:Security></S:Header><S:Body></S:Body></S:Envelope>`))
}

// A SAML key identifier names an assertion in the message by its ID (SAML
// Token Profile 1.1.1): the transform digests that assertion, never an
// X.509 token built from what ResolveSecurityToken returns. Any other key
// identifier that is not an X.509 one names a token the transform cannot
// reproduce, and is refused.
func TestSTRTransformSAMLKeyIdentifier(t *testing.T) {
	key := newKey(t, rsaKey)
	resolve := func(*xdm.Node) (*x509.Certificate, error) { return key.Certificate, nil }
	const (
		saml1   = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="_a1" MajorVersion="1" MinorVersion="1"/>`
		saml2   = `<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2" Version="2.0"/>`
		ki1     = `<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">_a1</wsse:KeyIdentifier>`
		ki2     = `<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID"> _a2 </wsse:KeyIdentifier>`
		ekSHA1  = `<wsse:KeyIdentifier EncodingType="` + xmlsec.BSTEncodingBase64 + `" ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1">AAAA</wsse:KeyIdentifier>`
		kerbKI  = `<wsse:KeyIdentifier EncodingType="` + xmlsec.BSTEncodingBase64 + `" ValueType="http://docs.oasis-open.org/wss/oasis-wss-kerberos-tokenprofile-1.1#Kerberosv5APREQSHA1">AAAA</wsse:KeyIdentifier>`
		wantSA1 = `<saml:Assertion xmlns="" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" AssertionID="_a1" MajorVersion="1" MinorVersion="1"></saml:Assertion>`
		wantSA2 = `<saml2:Assertion xmlns="" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a2" Version="2.0"></saml2:Assertion>`
	)
	sign := func(doc *xdm.Node) (*xdm.Node, error) {
		return dsig.Sign(doc, key, dsig.SignOptions{
			SignatureAlgorithm:        xmlsec.SigRSASHA256,
			CanonicalizationAlgorithm: string(c14n.Exclusive10),
			References:                []dsig.Reference{{URI: "#str", Transforms: strTransform, DigestAlgorithm: xmlsec.DigestSHA256}},
			ResolveSecurityToken:      resolve,
		})
	}
	for name, c := range map[string]struct{ ki, want string }{
		"SAML 1.1": {ki1, wantSA1},
		"SAML 2.0": {ki2, wantSA2},
	} {
		doc := samlSTRDoc(t, saml1+saml2, c.ki)
		sig, err := sign(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := sha256.Sum256([]byte(c.want))
		if !strings.Contains(string(serialize(t, sig)), base64.StdEncoding.EncodeToString(want[:])) {
			t.Fatalf("%s: digest is not the assertion's:\n%s", name, serialize(t, sig))
		}
		xmltree.DocumentElement(doc).ChildElements()[0].ChildElements()[0].AppendChild(sig)
		cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate})
		if err != nil || len(cov.SignedTokens) != 1 || cov.SignedTokens[0].Name.Local != "Assertion" {
			t.Fatalf("%s: %v, %+v", name, err, cov)
		}
	}

	for name, c := range map[string]struct {
		tokens, ki string
		want       error
	}{
		"assertion not in the message": {saml2, ki1, xmlsec.ErrSecurityTokenUnavailable},
		"ID on another element":        {`<x wsu:Id="_a1"/>`, ki1, xmlsec.ErrSecurityTokenUnavailable},
		"SAML 2.0 ID on a 1.1 assertion": {`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ID="_a2"/>`, ki2,
			xmlsec.ErrSecurityTokenUnavailable},
		"ID twice":         {saml1 + `<x wsu:Id="_a1"/>`, ki1, xmlsec.ErrAmbiguousID},
		"EncryptedKeySHA1": {saml1, ekSHA1, xmlsec.ErrUnsupportedKeyInfo},
		"Kerberos":         {saml1, kerbKI, xmlsec.ErrUnsupportedKeyInfo},
	} {
		if _, err := sign(samlSTRDoc(t, c.tokens, c.ki)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The canonicalization of the STR Dereference Transform is any the
// allow-list admits: Inclusive C14N, as in the section 8.3 example,
// verifies when allowed and is refused when not, and under StrictBSP, which
// requires Exclusive C14N (R5404).
func TestSTRTransformCanonicalization(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := string(signSTR(t, key, directSTR(t), nil))
	exc := `<ds:CanonicalizationMethod Algorithm="` + string(c14n.Exclusive10) + `"><ec:InclusiveNamespaces xmlns:ec="` + xmlsec.NSExcC14N +
		`" PrefixList="#default"></ec:InclusiveNamespaces></ds:CanonicalizationMethod>`
	inc := strings.Replace(signed, exc, `<ds:CanonicalizationMethod Algorithm="`+string(c14n.Inclusive10)+`"></ds:CanonicalizationMethod>`, 1)
	if inc == signed {
		t.Fatalf("no STR canonicalization:\n%s", signed)
	}
	doc := parse(t, []byte(inc))
	sig := findSignature(doc)
	// The token's Inclusive C14N, with the xmlns="" section 8.3 adds: the
	// envelope has no default namespace.
	var bst *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if e.IsElement(xmlsec.NSWSSE, "BinarySecurityToken") {
			bst = e
		}
	})
	b, err := c14n.Bytes(bst, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `<wsse:BinarySecurityToken `, `<wsse:BinarySecurityToken xmlns="" `, 1))
	d := sha256.Sum256(b)
	refs := sig.ChildElements()[0].ChildElements()
	digest := refs[len(refs)-1].ChildElements()[2]
	digest.Children[0].Value = base64.StdEncoding.EncodeToString(d[:])
	resignSI(t, sig, c14n.Exclusive10)

	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate}); err != nil {
		t.Fatalf("Inclusive C14N, default allow-list: %v", err)
	}
	allow := []string{string(c14n.Exclusive10), string(c14n.Inclusive10)}
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate, AllowedCanonicalizationAlgorithms: allow}); err != nil {
		t.Fatalf("Inclusive C14N allowed: %v", err)
	}
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate, AllowedCanonicalizationAlgorithms: allow[:1]}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("Inclusive C14N not allowed: %v", err)
	}
	// StrictBSP also refuses the ds:X509Data KeyInfo (R5417); without it,
	// the canonicalization decides.
	sig.Children = slices.DeleteFunc(sig.Children, func(n *xdm.Node) bool { return n.IsElement(xmlsec.NSDSig, "KeyInfo") })
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate, StrictBSP: true}); !errors.Is(err, xmlsec.ErrMalformed) ||
		!strings.Contains(err.Error(), "R5404") {
		t.Fatalf("Inclusive C14N under StrictBSP: %v", err)
	}
}
