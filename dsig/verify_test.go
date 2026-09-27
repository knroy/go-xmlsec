package dsig_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

var covECKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// --- Hand-built signatures for the structural checks ------------------------

const (
	covExc    = string(c14n.Exclusive10)
	covCM     = `<ds:CanonicalizationMethod Algorithm="` + covExc + `"/>`
	covSM     = `<ds:SignatureMethod Algorithm="` + xmlsec.SigRSASHA256 + `"/>`
	covTr     = `<ds:Transforms><ds:Transform Algorithm="` + covExc + `"/></ds:Transforms>`
	covDigest = `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue>AAAA</ds:DigestValue>`
	covRef    = `<ds:Reference URI="#a">` + covTr + covDigest + `</ds:Reference>`
	covSV     = `<ds:SignatureValue>AAAA</ds:SignatureValue>`
	covIN     = `<ec:InclusiveNamespaces xmlns:ec="` + xmlsec.NSExcC14N + `" PrefixList="p"/>`
)

func covSI(inner string) string { return `<ds:SignedInfo>` + inner + `</ds:SignedInfo>` }

func covKI(inner string) string {
	return covSI(covCM+covSM+covRef) + covSV + `<ds:KeyInfo>` + inner + `</ds:KeyInfo>`
}

func covTransforms(algs ...string) string {
	var b strings.Builder
	for _, a := range algs {
		b.WriteString(`<ds:Transform Algorithm="` + a + `"/>`)
	}
	return b.String()
}

// covDoc places a ds:Signature with the given content in a document that
// has an element with wsu:Id "a" and one, not a token, with wsu:Id "nb".
func covDoc(sigContent string) string {
	return `<r xmlns:wsu="` + xmlsec.NSWSU + `" xmlns:wsse="` + xmlsec.NSWSSE + `" xmlns:p="urn:p">` +
		`<a wsu:Id="a">x</a><z wsu:Id="nb"/>` +
		`<ds:Signature xmlns:ds="` + xmlsec.NSDSig + `">` + sigContent + `</ds:Signature></r>`
}

func TestVerifyStructure(t *testing.T) {
	rsaCert := newKey(t, rsaKey).Certificate
	ecCert := newKey(t, covECKey).Certificate
	withCert := dsig.VerifyOptions{Certificate: rsaCert}
	zeros64 := base64.StdEncoding.EncodeToString(make([]byte, 64))
	ecSM := `<ds:SignatureMethod Algorithm="` + xmlsec.SigECDSASHA256 + `"/>`

	cases := []struct {
		name string
		sig  string
		opts dsig.VerifyOptions
		want error // nil: any error
	}{
		// ds:Signature
		{"empty signature", ``, withCert, xmlsec.ErrMalformed},
		{"missing SignedInfo", covSV, withCert, xmlsec.ErrMalformed},
		{"SignatureValue first", covSV + covSI(covCM+covSM+covRef), withCert, xmlsec.ErrMalformed},
		{"SignatureValue not base64", covSI(covCM+covSM+covRef) + `<ds:SignatureValue>!!</ds:SignatureValue>`, withCert, xmlsec.ErrMalformed},
		{"unexpected element", covSI(covCM+covSM+covRef) + covSV + `<ds:Manifest/>`, withCert, xmlsec.ErrMalformed},
		{"KeyInfo after Object", covSI(covCM+covSM+covRef) + covSV + `<ds:Object/><ds:KeyInfo/>`, withCert, xmlsec.ErrMalformed},
		{"two KeyInfo", covSI(covCM+covSM+covRef) + covSV + `<ds:KeyInfo/><ds:KeyInfo/>`, withCert, xmlsec.ErrMalformed},

		// ds:SignedInfo
		{"no Reference", covSI(covCM + covSM), withCert, xmlsec.ErrMalformed},
		{"SignatureMethod first", covSI(covSM+covCM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"SignatureMethod with children", covSI(covCM+`<ds:SignatureMethod Algorithm="`+xmlsec.SigRSASHA256+`"><ds:HMACOutputLength>8</ds:HMACOutputLength></ds:SignatureMethod>`+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"CanonicalizationMethod with unknown child", covSI(`<ds:CanonicalizationMethod Algorithm="`+covExc+`"><x/></ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"InclusiveNamespaces under inclusive CanonicalizationMethod", covSI(`<ds:CanonicalizationMethod Algorithm="`+string(c14n.Inclusive10)+`">`+covIN+`</ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrMalformed},
		{"non-Reference in SignedInfo", covSI(covCM+covSM+`<ds:Object/>`) + covSV, withCert, xmlsec.ErrMalformed},

		// ds:Reference
		{"Reference without URI", covSI(covCM+covSM+`<ds:Reference>`+covTr+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"too many transforms", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms>`+strings.Repeat(`<ds:Transform Algorithm="`+covExc+`"/>`, dsig.MaxTransformsPerReference+1)+`</ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrLimitExceeded},
		{"non-Transform in Transforms", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:XPath/></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"XPath transform not opted in", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+xmlsec.TransformXPath+`"><ds:XPath>1</ds:XPath></ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrTransformRefused},
		{"InclusiveNamespaces under inclusive Transform", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+string(c14n.Inclusive10)+`">`+covIN+`</ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"two InclusiveNamespaces", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms><ds:Transform Algorithm="`+covExc+`">`+covIN+covIN+`</ds:Transform></ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"missing DigestValue", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"extra element in Reference", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+covDigest+`<ds:Object/></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},
		{"DigestValue not base64", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="`+xmlsec.DigestSHA256+`"/><ds:DigestValue>!!</ds:DigestValue></ds:Reference>`) + covSV, withCert, xmlsec.ErrMalformed},

		// Allow-lists, checked before any cryptographic work.
		{"unknown signature algorithm", covSI(covCM+`<ds:SignatureMethod Algorithm="urn:x"/>`+covRef) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown canonicalization", covSI(`<ds:CanonicalizationMethod Algorithm="urn:x"/>`+covSM+covRef) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown digest", covSI(covCM+covSM+`<ds:Reference URI="#a">`+covTr+`<ds:DigestMethod Algorithm="urn:x"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>`) + covSV, withCert, xmlsec.ErrAlgorithmNotAllowed},
		{"transform canonicalization outside allow-list", covSI(covCM+covSM+`<ds:Reference URI="#a"><ds:Transforms>`+covTransforms(string(c14n.Inclusive10))+`</ds:Transforms>`+covDigest+`</ds:Reference>`) + covSV,
			dsig.VerifyOptions{Certificate: rsaCert, AllowedCanonicalizationAlgorithms: []string{covExc}}, xmlsec.ErrAlgorithmNotAllowed},

		// ds:KeyInfo
		{"empty KeyInfo", covKI(``), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyInfo with two children", covKI(`<ds:KeyName>a</ds:KeyName><ds:KeyName>b</ds:KeyName>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Data with unparsable certificates", covKI(`<ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"X509Data with an empty issuer serial", covKI(`<ds:X509Data><ds:X509IssuerSerial/></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"X509Data with issuer serial only", covKI(`<ds:X509Data><ds:X509IssuerSerial><ds:X509IssuerName>CN=x</ds:X509IssuerName><ds:X509SerialNumber>1</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"X509Certificate not base64", covKI(`<ds:X509Data><ds:X509Certificate>!!</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"X509Certificate not DER", covKI(`<ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data>`), dsig.VerifyOptions{}, nil},
		{"STR to missing token", covKI(`<wsse:SecurityTokenReference><wsse:Reference URI="#missing"/></wsse:SecurityTokenReference>`), dsig.VerifyOptions{}, xmlsec.ErrIDNotFound},
		{"STR to non-token", covKI(`<wsse:SecurityTokenReference><wsse:Reference URI="#nb"/></wsse:SecurityTokenReference>`), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"no KeyInfo and no certificate", covSI(covCM+covSM+covRef) + covSV, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},

		// Signature value against the key.
		{"empty PrefixList reaches the signature check", covSI(`<ds:CanonicalizationMethod Algorithm="`+covExc+`"><ec:InclusiveNamespaces xmlns:ec="`+xmlsec.NSExcC14N+`" PrefixList=""/></ds:CanonicalizationMethod>`+covSM+covRef) + covSV, withCert, xmlsec.ErrSignatureInvalid},
		{"RSA key with an ECDSA algorithm", covSI(covCM+ecSM+covRef) + covSV, withCert, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA key with an RSA algorithm", covSI(covCM+covSM+covRef) + covSV, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrUnsupportedAlgorithm},
		{"ECDSA value of the wrong length", covSI(covCM+ecSM+covRef) + covSV, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrSignatureInvalid},
		{"ECDSA value of zeros", covSI(covCM+ecSM+covRef) + `<ds:SignatureValue>` + zeros64 + `</ds:SignatureValue>`, dsig.VerifyOptions{Certificate: ecCert}, xmlsec.ErrSignatureInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(covDoc(c.sig)))
			_, err := dsig.Verify(doc, findSignature(doc), c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestVerifyArguments(t *testing.T) {
	doc := parse(t, []byte(covDoc(covSI(covCM+covSM+covRef)+covSV)))
	other := parse(t, []byte(covDoc(covSI(covCM+covSM+covRef)+covSV)))
	cases := []struct {
		name     string
		doc, sig *xdm.Node
		want     error // nil: any error
	}{
		{"nil doc", nil, findSignature(doc), xmlsec.ErrMalformed},
		{"nil signature", doc, nil, xmlsec.ErrMalformed},
		{"not a signature", doc, xmltree.DocumentElement(doc), xmlsec.ErrMalformed},
		{"signature from another document", doc, findSignature(other), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dsig.Verify(c.doc, c.sig, dsig.VerifyOptions{})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestCoverage(t *testing.T) {
	c := &dsig.Coverage{SignedElementIDs: []string{"a", "b"}, SignedAttachmentIDs: []string{"x"}}
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"all elements", c.Covers("a", "b"), true},
		{"no elements asked", c.Covers(), true},
		{"one element missing", c.Covers("a", "c"), false},
		{"attachment", c.CoversAttachments("x"), true},
		{"attachment missing", c.CoversAttachments("x", "y"), false},
		{"element ID is not an attachment ID", c.CoversAttachments("a"), false},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: got %v", tc.name, tc.got)
		}
	}
}

// --- Signing ---------------------------------------------------------------

func (s covSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return s.out, s.err }

func (covOpaqueSigner) Public() crypto.PublicKey { return struct{}{} }

func TestKeyInfoNone(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := covSignAndPlace(t, key, dsig.KeyInfoNone, nil, func(id string) []dsig.Reference {
		return []dsig.Reference{{URI: "#" + id, ID: "ref-1", Type: "urn:type", Transforms: excC14N, DigestAlgorithm: xmlsec.DigestSHA256}}
	})
	if strings.Contains(string(signed), "KeyInfo") {
		t.Fatal("KeyInfoNone emitted ds:KeyInfo")
	}
	cases := []struct {
		name string
		cert bool
		want error
	}{
		{"with VerifyOptions.Certificate", true, nil},
		{"without VerifyOptions.Certificate", false, xmlsec.ErrUnsupportedKeyInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, signed)
			var opts dsig.VerifyOptions
			if c.cert {
				opts.Certificate = key.Certificate
			}
			cov, err := dsig.Verify(doc, findSignature(doc), opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (cov.KeyInfoForm != dsig.KeyInfoNone || cov.References[0].Type != "urn:type") {
				t.Fatalf("form %d, references %+v", cov.KeyInfoForm, cov.References)
			}
		})
	}
}

// resignSI re-signs ds:SignedInfo in place with rsaKey, after a test has
// altered it, so only the property under test decides the outcome.
func resignSI(t *testing.T, sig *xdm.Node, alg c14n.Algorithm) {
	t.Helper()
	si, value := sig.ChildElements()[0], sig.ChildElements()[1]
	h := sha256.New()
	if _, err := c14n.Digest(h, si, c14n.Options{Algorithm: alg}); err != nil {
		t.Fatal(err)
	}
	v, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	value.Children[0].Value = base64.StdEncoding.EncodeToString(v)
}

// signForImplicit signs doc with an enveloped reference whose explicit
// transform is Canonical XML 1.0, then removes that transform: the digest
// is unchanged, since Canonical XML 1.0 is exactly what is then implied.
func signForImplicit(t *testing.T, siAlg c14n.Algorithm) (*xdm.Node, *xdm.Node, xmlsec.KeyProvider) {
	t.Helper()
	key := newKey(t, rsaKey)
	tree, err := xmlsec.Parse([]byte(`<r><a>x</a></r>`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := dsig.SignEnveloped(tree.Root, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(siAlg),
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Inclusive10)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, signed)
	sig := findSignature(doc)
	transforms := sig.ChildElements()[0].ChildElements()[2].ChildElements()[0]
	transforms.Children = transforms.Children[:1] // enveloped-signature only
	resignSI(t, sig, siAlg)
	return doc, sig, key
}

// XML-DSig 4.4.3.2: a reference ending in a node set is canonicalized with
// Canonical XML 1.0. Most SMP software signs this way.
func TestImplicitCanonicalization(t *testing.T) {
	doc, sig, key := signForImplicit(t, c14n.Inclusive10)
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate})
	if err != nil || !cov.WholeDocumentSigned {
		t.Fatalf("implicit C14N: %v", err)
	}

	// The implied algorithm is subject to the allow-list like a named one.
	doc, sig, key = signForImplicit(t, c14n.Exclusive10)
	_, err = dsig.Verify(doc, sig, dsig.VerifyOptions{
		Certificate:                       key.Certificate,
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
	})
	if !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("implicit C14N outside the allow-list: %v", err)
	}

	// A same-document reference with no transforms at all.
	key = newKey(t, rsaKey)
	tree, err := xmlsec.Parse([]byte(`<r xmlns:wsu="` + xmlsec.NSWSU + `"><a wsu:Id="a">x</a></r>`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := dsig.Sign(tree.Root, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "#a", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Inclusive10)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := s.ChildElements()[0].ChildElements()[2]
	ref.Children = ref.Children[1:] // drop ds:Transforms
	xmltree.DocumentElement(tree.Root).AppendChild(s)
	resignSI(t, s, c14n.Exclusive10)
	if cov, err := dsig.Verify(tree.Root, s, dsig.VerifyOptions{Certificate: key.Certificate}); err != nil || !cov.Covers("a") {
		t.Fatalf("no transforms: %v", err)
	}
}

// ds:X509Data may carry the subject name, issuer-serial or SKI of its
// certificate, as most SMP software emits; they must describe it. A CRL and a
// ds:KeyName beside are reported, not used.
func TestX509DataDescriptiveElements(t *testing.T) {
	add := func(parent *xdm.Node, local, text string) *xdm.Node {
		e := xmltree.Element(parent, "ds", xmlsec.NSDSig, local)
		xmltree.Text(e, text)
		return e
	}
	keyInfo := func(t *testing.T) (*xdm.Node, *xdm.Node, *xdm.Node) {
		doc := parse(t, signEnveloped(t, newKey(t, rsaKey), xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
		sig := findSignature(doc)
		ki := sig.ChildElements()[2]
		return doc, sig, ki
	}
	cases := []struct {
		name string
		mod  func(ki *xdm.Node)
		want error
	}{
		{"subject name and issuer-serial", func(ki *xdm.Node) {
			x := ki.ChildElements()[0]
			add(x, "X509SubjectName", "CN=test")
			is := xmltree.Element(x, "ds", xmlsec.NSDSig, "X509IssuerSerial")
			add(is, "X509IssuerName", "CN=test")
			add(is, "X509SerialNumber", "1")
		}, nil},
		// A stale descriptor beside the certificate selects nothing and is
		// ignored unless VerifyOptions.StrictX509Data (TestX509Descriptors).
		{"a second X509Data with another SKI", func(ki *xdm.Node) {
			add(xmltree.Element(ki, "ds", xmlsec.NSDSig, "X509Data"), "X509SKI", "AAAA")
		}, nil},
		{"another subject name", func(ki *xdm.Node) { add(ki.ChildElements()[0], "X509SubjectName", "CN=other") }, nil},
		{"two certificates", func(ki *xdm.Node) {
			x := ki.ChildElements()[0]
			add(x, "X509Certificate", x.ChildElements()[0].StringValue())
		}, xmlsec.ErrUnsupportedKeyInfo},
		{"a CRL", func(ki *xdm.Node) { add(ki.ChildElements()[0], "X509CRL", "AAAA") }, nil},
		{"a KeyName beside X509Data", func(ki *xdm.Node) { add(ki, "KeyName", "k") }, nil},
		{"no certificate", func(ki *xdm.Node) { ki.Children = nil }, xmlsec.ErrUnsupportedKeyInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig, ki := keyInfo(t)
			c.mod(ki)
			if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// An HMAC SignatureMethod carries HMACOutputLength as a child. It is refused
// as a disallowed algorithm, not as a malformed element.
func TestHMACReportedAsNotAllowed(t *testing.T) {
	doc := parse(t, signEnveloped(t, newKey(t, rsaKey), xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
	sig := findSignature(doc)
	sm := sig.ChildElements()[0].ChildElements()[1]
	sm.Attr("", "Algorithm").Value = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	xmltree.Text(xmltree.Element(sm, "ds", xmlsec.NSDSig, "HMACOutputLength"), "160")
	if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("got %v", err)
	}
}

// TrustKey sees the signer's key and certificate before any digest is
// computed: a tampered message whose key the hook refuses fails as
// untrusted, not as a digest mismatch.
func TestTrustKey(t *testing.T) {
	key := newKey(t, rsaKey)
	signed := signEnveloped(t, key, xmlsec.SigRSASHA256, xmlsec.DigestSHA256)

	var seen *x509.Certificate
	var seenKey crypto.PublicKey
	accept := func(c *x509.Certificate, k crypto.PublicKey) error { seen, seenKey = c, k; return nil }
	doc := parse(t, signed)
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{TrustKey: accept}); err != nil {
		t.Fatal(err)
	}
	if !seen.Equal(key.Certificate) || !key.Certificate.PublicKey.(*rsa.PublicKey).Equal(seenKey) {
		t.Fatal("hook did not see the signer's certificate and key")
	}

	errNotOurs := errors.New("not a known sender")
	refuse := func(*x509.Certificate, crypto.PublicKey) error { return errNotOurs }
	tampered := parse(t, []byte(strings.Replace(string(signed), "example.com", "evil.com", 1)))
	_, err := dsig.Verify(tampered, findSignature(tampered), dsig.VerifyOptions{TrustKey: refuse})
	if !errors.Is(err, xmlsec.ErrUntrusted) || !errors.Is(err, errNotOurs) {
		t.Fatalf("got %v", err)
	}
}

func TestRequireExplicitCanonicalization(t *testing.T) {
	doc, sig, key := signForImplicit(t, c14n.Inclusive10)
	_, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate, RequireExplicitCanonicalization: true})
	if !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("implied C14N with RequireExplicitCanonicalization: %v", err)
	}
	// A reference that names its canonicalization is unaffected.
	doc = parse(t, signEnveloped(t, key, xmlsec.SigRSASHA256, xmlsec.DigestSHA256))
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: key.Certificate, RequireExplicitCanonicalization: true}); err != nil {
		t.Fatal(err)
	}
}

// The SwA signature transforms canonicalize an XML attachment with
// Exclusive C14N, so a caller who does not allow it is refused, even when
// everything else in the signature is inclusive.
func TestAttachmentCanonicalizationAllowList(t *testing.T) {
	key := newKey(t, rsaKey)
	atts := attachments(t, "payload")
	tree, err := xmlsec.Parse([]byte(`<r><a>x</a></r>`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := dsig.SignEnveloped(tree.Root, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Inclusive10),
		References: []dsig.Reference{
			{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Inclusive10)}}},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformAttachmentContentSignature}}},
		},
		Attachments: atts,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, signed)
	opts := dsig.VerifyOptions{Certificate: key.Certificate, Attachments: atts,
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Inclusive10)}}
	if _, err := dsig.Verify(doc, findSignature(doc), opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("inclusive-only allow-list: %v", err)
	}
	opts.AllowedCanonicalizationAlgorithms = append(opts.AllowedCanonicalizationAlgorithms, string(c14n.Exclusive10))
	if cov, err := dsig.Verify(doc, findSignature(doc), opts); err != nil || !cov.CoversAttachments("att-1@example.com") {
		t.Fatalf("with Exclusive C14N allowed: %v", err)
	}
}

// XML-DSig 4.4.3.1: a Reference may omit URI, on at most one Reference, when
// the application knows the data object. ResolveOmittedURI supplies it; its
// octets go through the Reference's transforms.
func TestOmittedURI(t *testing.T) {
	digest := func(s string) string {
		d := sha256.Sum256([]byte(s))
		return base64.StdEncoding.EncodeToString(d[:])
	}
	ref := func(digestOf string, algs ...string) string {
		ts := ""
		if len(algs) > 0 {
			ts = `<ds:Transforms>` + covTransforms(algs...) + `</ds:Transforms>`
		}
		return `<ds:Reference>` + ts + `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue>` +
			digest(digestOf) + `</ds:DigestValue></ds:Reference>`
	}
	octets := func(s string) func() ([]byte, error) { return func() ([]byte, error) { return []byte(s), nil } }
	errResolve := errors.New("no such object")

	cases := []struct {
		name    string
		refs    string
		resolve func() ([]byte, error)
		want    error // nil: success
	}{
		{"no transforms", ref("hello!"), octets("hello!"), nil},
		{"base64", ref("hello!", xmlsec.TransformBase64), octets("aGVs bG8h"), nil},
		{"canonicalization parses the octets", ref(`<a b="1"></a>`, covExc), octets(`<a  b='1'/>`), nil},
		{"beside a URI reference", ref("hello!") + `<ds:Reference URI="#a">` + covTr + covDigest + `</ds:Reference>`, octets("hello!"), xmlsec.ErrDigestMismatch},
		{"other octets", ref("hello!"), octets("hello?"), xmlsec.ErrDigestMismatch},
		{"no resolver", ref("hello!"), nil, xmlsec.ErrMalformed},
		{"resolver fails", ref("hello!"), func() ([]byte, error) { return nil, errResolve }, errResolve},
		{"two omitted URIs", ref("hello!") + ref("hello!"), octets("hello!"), xmlsec.ErrMalformed},
		{"enveloped on octets", ref("hello!", xmlsec.TransformEnvelopedSignature), octets("hello!"), xmlsec.ErrMalformed},
		{"octets with a DOCTYPE", ref("", covExc), octets(`<!DOCTYPE a><a/>`), xmlsec.ErrMalformed},
		{"SwA transform", ref("", xmlsec.TransformAttachmentContentSignature), octets("x"), xmlsec.ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse(t, []byte(covDoc(covSI(covCM+covSM+c.refs)+covSV)))
			sig := findSignature(doc)
			resignSI(t, sig, c14n.Exclusive10)
			cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
				PublicKey:                       &rsaKey.PublicKey,
				ResolveOmittedURI:               c.resolve,
				RequireExplicitCanonicalization: true, // an omitted URI is not a same-document reference
			})
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (!cov.OmittedURISigned || cov.WholeDocumentSigned || len(cov.References) != 1 || cov.References[0].URI != "") {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}

// StrictSecurityTokenReference applies the Basic Security Profile rules to
// the token reference: a message this library builds passes, and one whose
// reference lacks a ValueType passes only in the default, lenient mode.
func TestStrictSecurityTokenReference(t *testing.T) {
	signed, _, _ := signAS4(t, newKey(t, rsaKey))
	opts := as4Allow
	opts.Attachments = attachments(t, "payload")
	opts.StrictSecurityTokenReference = true
	doc := parse(t, signed)
	if _, err := dsig.Verify(doc, findSignature(doc), opts); err != nil {
		t.Fatalf("our own message, strict: %v", err)
	}

	loose := parse(t, []byte(strings.Replace(string(signed), ` ValueType="`+xmlsec.BSTValueTypeX509v3+`"></wsse:Reference>`, `></wsse:Reference>`, 1)))
	if _, err := dsig.Verify(loose, findSignature(loose), opts); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("no ValueType, strict: %v", err)
	}
	opts.StrictSecurityTokenReference = false
	if _, err := dsig.Verify(loose, findSignature(loose), opts); err != nil {
		t.Fatalf("no ValueType, lenient: %v", err)
	}
}
