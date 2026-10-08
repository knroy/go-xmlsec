package dsig_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// testPKI is a root CA, an intermediate CA it issued, and a leaf the
// intermediate issued for rsaKey. The leaf's subject needs escaping and
// carries an e-mail address, which RFC 4514 renders as #hex.
type testPKI struct {
	root, inter, leaf *x509.Certificate
	key               xmlsec.KeyProvider
}

func issue(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl.NotBefore, tmpl.NotAfter = time.Unix(0, 0), time.Unix(1<<32, 0)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	rootKey, interKey := mustEC(p384Key.Curve), mustEC(p384Key.Curve)
	ca := func(serial int64, cn string, ski byte) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{ski}}
	}
	root := ca(1, "Root", 1)
	root = issue(t, root, root, rootKey.Public(), rootKey)
	inter := issue(t, ca(2, "Intermediate", 2), root, interKey.Public(), rootKey)
	leaf := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(1234567890123),
		Subject: pkix.Name{CommonName: `Leaf, "quoted" +plus`, Organization: []string{"Example Org"}, Country: []string{"NO"},
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "leaf@example.com"}}},
		SubjectKeyId: []byte{3, 3, 3},
	}, inter, &rsaKey.PublicKey, interKey)
	return testPKI{root, inter, leaf, xmlsec.KeyProvider{Signer: rsaKey, Certificate: leaf}}
}

// strangerCert is a self-signed certificate for a key of its own.
func strangerCert(t *testing.T) *x509.Certificate {
	k := mustEC(p384Key.Curve)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Stranger"}}
	return issue(t, tmpl, tmpl, k.Public(), k)
}

// signPKI signs the metadata document enveloped with key, letting set
// adjust the options.
func signPKI(t *testing.T, key xmlsec.KeyProvider, set func(o *dsig.SignOptions)) ([]byte, error) {
	t.Helper()
	return signPKIDoc(t, metadata, key, set)
}

// signPKIDoc is signPKI for another document.
func signPKIDoc(t *testing.T, doc string, key xmlsec.KeyProvider, set func(o *dsig.SignOptions)) ([]byte, error) {
	t.Helper()
	o := dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(c14n.Exclusive10)}}}},
		KeyInfo: dsig.KeyInfoX509Data,
	}
	set(&o)
	return dsig.SignEnveloped(parse(t, []byte(doc)), key, o)
}

var allDescriptors = []dsig.X509Descriptor{dsig.X509IssuerSerial, dsig.X509SKI, dsig.X509SubjectName, dsig.X509Digest}

// XML-DSig 4.5.4: a certificate chain in ds:X509Data, with every descriptor
// of the signing certificate and a ds:KeyName, signs and verifies; the
// verifier finds the leaf and reports the rest.
func TestX509Chain(t *testing.T) {
	p := newPKI(t)
	signed, err := signPKI(t, p.key, func(o *dsig.SignOptions) {
		o.Chain, o.X509Descriptors, o.KeyName = []*x509.Certificate{p.inter, p.root}, allDescriptors, "signing key"
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<ds:KeyName>signing key</ds:KeyName>", "<ds:X509IssuerSerial>", "<ds:X509SKI>", "<ds:X509SubjectName>",
		`<dsig11:X509Digest xmlns:dsig11="` + xmlsec.NSDSig11 + `" Algorithm="` + xmlsec.DigestSHA256 + `">`} {
		if !strings.Contains(string(signed), want) {
			t.Errorf("no %s in\n%s", want, signed)
		}
	}
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Certificate.Equal(p.leaf) || len(cov.Intermediates) != 2 || !cov.Intermediates[0].Equal(p.inter) ||
		!cov.Intermediates[1].Equal(p.root) || cov.KeyName != "signing key" || cov.KeyInfoForm != dsig.KeyInfoX509Data {
		t.Fatalf("coverage %+v", cov)
	}

	// A pinned key: the description is read, and not reported.
	cov, err = dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Certificate: p.leaf})
	if err != nil || cov.Intermediates != nil || cov.KeyName != "" {
		t.Fatalf("pinned: %v, %+v", err, cov)
	}
}

func x509Cert(c *x509.Certificate) string {
	return `<ds:X509Certificate>` + b64(c.Raw) + `</ds:X509Certificate>`
}

func issuerSerial(name, serial string) string {
	return `<ds:X509IssuerSerial><ds:X509IssuerName>` + name + `</ds:X509IssuerName><ds:X509SerialNumber>` + serial + `</ds:X509SerialNumber></ds:X509IssuerSerial>`
}

func x509Digest(alg string, b []byte) string {
	return `<dsig11:X509Digest xmlns:dsig11="` + xmlsec.NSDSig11 + `" Algorithm="` + alg + `">` + b64(b) + `</dsig11:X509Digest>`
}

// Under StrictX509Data every descriptor beside a certificate must describe
// it: XML-DSig 4.5.4 says they "MUST refer to the certificate or
// certificates containing the validation key". By default a stale one is
// ignored, as it selects nothing.
func TestX509Descriptors(t *testing.T) {
	p := newPKI(t)
	leaf := x509Cert(p.leaf)
	sum256 := sha256.Sum256(p.leaf.Raw)
	sum1 := sha1.Sum(p.leaf.Raw)
	issuer := p.leaf.Issuer.String()
	other := newPKI(t)
	sha1Allowed := dsig.VerifyOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256, xmlsec.DigestSHA1}, StrictX509Data: true}
	strict := dsig.VerifyOptions{StrictX509Data: true}
	var many strings.Builder
	for range 17 {
		many.WriteString(leaf)
	}
	cases := []struct {
		name string
		data string
		opts dsig.VerifyOptions
		want error
	}{
		{"issuer-serial", leaf + issuerSerial(issuer, "1234567890123"), dsig.VerifyOptions{}, nil},
		{"subject name", leaf + `<ds:X509SubjectName>` + p.leaf.Subject.String() + `</ds:X509SubjectName>`, dsig.VerifyOptions{}, nil},
		{"SKI", leaf + `<ds:X509SKI>AwMD</ds:X509SKI>`, dsig.VerifyOptions{}, nil},
		{"X509Digest", leaf + x509Digest(xmlsec.DigestSHA256, sum256[:]), dsig.VerifyOptions{}, nil},
		{"X509Digest SHA-1, named", leaf + x509Digest(xmlsec.DigestSHA1, sum1[:]), sha1Allowed, nil},
		{"foreign child ignored", leaf + `<x:Hint xmlns:x="urn:x"/>`, dsig.VerifyOptions{}, nil},

		{"another serial", leaf + issuerSerial(issuer, "1"), strict, xmlsec.ErrUnsupportedKeyInfo},
		{"another serial, not strict", leaf + issuerSerial(issuer, "1"), dsig.VerifyOptions{}, nil},
		{"another issuer", leaf + issuerSerial("CN=Root", "1234567890123"), strict, xmlsec.ErrUnsupportedKeyInfo},
		{"another issuer, not strict", leaf + issuerSerial("CN=Root", "1234567890123"), dsig.VerifyOptions{}, nil},
		{"another subject", leaf + `<ds:X509SubjectName>CN=Leaf</ds:X509SubjectName>`, strict, xmlsec.ErrUnsupportedKeyInfo},
		{"another subject, not strict", leaf + `<ds:X509SubjectName>CN=Leaf</ds:X509SubjectName>`, dsig.VerifyOptions{}, nil},
		{"another SKI", leaf + `<ds:X509SKI>AwM=</ds:X509SKI>`, strict, xmlsec.ErrUnsupportedKeyInfo},
		{"another SKI, not strict", leaf + `<ds:X509SKI>AwM=</ds:X509SKI>`, dsig.VerifyOptions{}, nil},
		{"another certificate's digest", leaf + x509Digest(xmlsec.DigestSHA256, other.leaf.Raw[:32]), strict, xmlsec.ErrUnsupportedKeyInfo},
		{"another certificate's digest, not strict", leaf + x509Digest(xmlsec.DigestSHA256, other.leaf.Raw[:32]), dsig.VerifyOptions{}, nil},
		{"X509Digest SHA-1, not named", leaf + x509Digest(xmlsec.DigestSHA1, sum1[:]), strict, xmlsec.ErrAlgorithmNotAllowed},
		{"X509Digest SHA-1, not named, not strict", leaf + x509Digest(xmlsec.DigestSHA1, sum1[:]), dsig.VerifyOptions{}, nil},
		{"X509Digest, unimplemented", leaf + x509Digest("urn:x", sum1[:]), dsig.VerifyOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA256, "urn:x"}, StrictX509Data: true}, xmlsec.ErrUnsupportedAlgorithm},

		// xmlsec1 describes every certificate it carries.
		{"descriptors of each certificate", leaf + x509Cert(p.inter) + `<ds:X509SKI>AwMD</ds:X509SKI><ds:X509SKI>Ag==</ds:X509SKI>` +
			issuerSerial(issuer, "1234567890123") + issuerSerial("CN=Root", "2") + `<ds:X509SubjectName>CN=Intermediate</ds:X509SubjectName>`, dsig.VerifyOptions{}, nil},
		{"a descriptor of a certificate not carried", leaf + `<ds:X509SKI>AwMD</ds:X509SKI><ds:X509SKI>Ag==</ds:X509SKI>`, strict, xmlsec.ErrUnsupportedKeyInfo},
		{"a descriptor of a certificate not carried, not strict", leaf + `<ds:X509SKI>AwMD</ds:X509SKI><ds:X509SKI>Ag==</ds:X509SKI>`, dsig.VerifyOptions{}, nil},
		{"SKI not base64", leaf + `<ds:X509SKI>!!</ds:X509SKI>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"empty subject name", leaf + `<ds:X509SubjectName> </ds:X509SubjectName>`, dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"serial not an integer", leaf + issuerSerial(issuer, "0x1"), dsig.VerifyOptions{}, xmlsec.ErrMalformed},
		{"unknown ds child", leaf + `<ds:X509Other/>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"17 certificates", many.String(), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		// XML-DSig 4.5.4: certificates for one key, such as a re-issue, are
		// one leaf; the first is the signing certificate.
		{"two leaves, one key", leaf + x509Cert(other.leaf) + x509Cert(p.inter), dsig.VerifyOptions{}, nil},
		{"two leaves", leaf + x509Cert(strangerCert(t)) + x509Cert(p.inter), dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
		{"a CRL alone", `<ds:X509CRL>AAAA</ds:X509CRL>`, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, sig := signedCovDoc(t, covKI(`<ds:X509Data>`+c.data+`</ds:X509Data>`))
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if err == nil && (!cov.Certificate.Equal(p.leaf) || cov.KeyInfoForm != dsig.KeyInfoX509Data) {
				t.Fatalf("coverage %+v", cov)
			}
			// With a pinned key the description is a hint, not an error.
			c.opts.Certificate = p.leaf
			if _, err := dsig.Verify(doc, sig, c.opts); err != nil && !errors.Is(err, xmlsec.ErrMalformed) {
				t.Fatalf("pinned: %v", err)
			}
		})
	}
}

// The certificates of ds:X509Data may come in any order, across several
// ds:X509Data; CRLs are reported.
func TestX509ChainOrderAndCRLs(t *testing.T) {
	p := newPKI(t)
	doc, sig := signedCovDoc(t, covKI(`<ds:X509Data>`+x509Cert(p.root)+x509Cert(p.inter)+`<ds:X509CRL>AQID</ds:X509CRL></ds:X509Data>`+
		`<ds:X509Data>`+x509Cert(p.leaf)+`<ds:X509CRL>BAU=</ds:X509CRL></ds:X509Data>`))
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Certificate.Equal(p.leaf) || len(cov.Intermediates) != 2 || !cov.Intermediates[0].Equal(p.root) ||
		!slices.EqualFunc(cov.CRLs, [][]byte{{1, 2, 3}, {4, 5}}, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("coverage %+v", cov)
	}
}

// ds:X509Data without a certificate goes to ResolveX509, which receives
// every descriptor; what it returns must match them.
func TestResolveX509(t *testing.T) {
	p := newPKI(t)
	sum := sha256.Sum256(p.leaf.Raw)
	issuer := p.leaf.Issuer.String()
	all := issuerSerial(issuer, "1234567890123") + `<ds:X509SKI>AwMD</ds:X509SKI><ds:X509SubjectName>` + p.leaf.Subject.String() +
		`</ds:X509SubjectName>` + x509Digest(xmlsec.DigestSHA256, sum[:])
	var got []dsig.X509Identifier
	var first *dsig.X509Identifier
	returning := func(c *x509.Certificate, err error) dsig.VerifyOptions {
		return dsig.VerifyOptions{ResolveX509: func(id dsig.X509Identifier) (*x509.Certificate, error) {
			got = append(got, id)
			if first == nil {
				first = &id
			}
			return c, err
		}}
	}
	errNotFound := errors.New("not found")
	cases := []struct {
		name  string
		data  string
		opts  dsig.VerifyOptions
		want  error
		calls int
	}{
		{"every descriptor", all, returning(p.leaf, nil), nil, 1},
		{"no resolver", all, dsig.VerifyOptions{}, xmlsec.ErrUnsupportedKeyInfo, 0},
		{"resolver error", all, returning(nil, errNotFound), errNotFound, 1},
		{"no certificate returned", all, returning(nil, nil), xmlsec.ErrUnsupportedKeyInfo, 1},
		{"another certificate returned", all, returning(p.inter, nil), xmlsec.ErrUnsupportedKeyInfo, 1},
		{"a certificate without its encoding", `<ds:X509SubjectName>CN=x</ds:X509SubjectName>`, returning(&x509.Certificate{PublicKey: &rsaKey.PublicKey}, nil), xmlsec.ErrUnsupportedKeyInfo, 1},
		{"a repeated descriptor", `<ds:X509SKI>AwMD</ds:X509SKI><ds:X509SKI>Ag==</ds:X509SKI>`, returning(p.leaf, nil), xmlsec.ErrUnsupportedKeyInfo, 0},
		{"a disallowed digest never reaches it", x509Digest(xmlsec.DigestSHA1, sum[:20]), returning(p.leaf, nil), xmlsec.ErrAlgorithmNotAllowed, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got = nil
			doc, sig := signedCovDoc(t, covKI(`<ds:X509Data>`+c.data+`</ds:X509Data>`))
			cov, err := dsig.Verify(doc, sig, c.opts)
			if !errors.Is(err, c.want) || len(got) != c.calls {
				t.Fatalf("got %v after %d calls, want %v", err, len(got), c.want)
			}
			if err == nil && (!cov.Certificate.Equal(p.leaf) || cov.KeyInfoForm != dsig.KeyInfoX509Descriptors) {
				t.Fatalf("coverage %+v", cov)
			}
			// Nothing is resolved for a pinned key.
			c.opts.PublicKey = &rsaKey.PublicKey
			if _, err := dsig.Verify(doc, sig, c.opts); err != nil && !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) || len(got) != c.calls {
				t.Fatalf("pinned: %v after %d calls", err, len(got))
			}
		})
	}
	id := *first
	if id.IssuerName != issuer || id.Serial.Int64() != 1234567890123 || string(id.SKI) != "\x03\x03\x03" ||
		id.SubjectName != p.leaf.Subject.String() || string(id.Digest) != string(sum[:]) || id.DigestAlgorithm != xmlsec.DigestSHA256 {
		t.Fatalf("identifier %+v", id)
	}
}

// Sign emits the descriptors alone for KeyInfoX509Descriptors, and refuses
// options that do not fit together.
func TestSignX509Options(t *testing.T) {
	p := newPKI(t)
	signed, err := signPKI(t, p.key, func(o *dsig.SignOptions) {
		o.KeyInfo, o.X509Descriptors = dsig.KeyInfoX509Descriptors, []dsig.X509Descriptor{dsig.X509Digest, dsig.X509IssuerSerial}
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(signed), "X509Certificate") {
		t.Fatalf("certificate emitted:\n%s", signed)
	}
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{ResolveX509: func(dsig.X509Identifier) (*x509.Certificate, error) { return p.leaf, nil }})
	if err != nil || cov.KeyInfoForm != dsig.KeyInfoX509Descriptors {
		t.Fatalf("%v, %+v", err, cov)
	}

	noSKI := *p.leaf
	noSKI.SubjectKeyId = nil
	var long []*x509.Certificate
	for range 16 {
		long = append(long, p.inter)
	}
	cases := []struct {
		name string
		key  xmlsec.KeyProvider
		set  func(o *dsig.SignOptions)
	}{
		{"descriptors with a raw key", p.key, func(o *dsig.SignOptions) { o.KeyInfo, o.X509Descriptors = dsig.KeyInfoKeyValue, allDescriptors }},
		{"chain with a raw key", p.key, func(o *dsig.SignOptions) { o.KeyInfo, o.Chain = dsig.KeyInfoKeyValue, []*x509.Certificate{p.inter} }},
		{"chain without certificate", p.key, func(o *dsig.SignOptions) {
			o.KeyInfo, o.Chain, o.X509Descriptors = dsig.KeyInfoX509Descriptors, []*x509.Certificate{p.inter}, allDescriptors
		}},
		{"no descriptors", p.key, func(o *dsig.SignOptions) { o.KeyInfo = dsig.KeyInfoX509Descriptors }},
		{"chain too long", p.key, func(o *dsig.SignOptions) { o.Chain = long }},
		{"signer not the leaf", p.key, func(o *dsig.SignOptions) { o.Chain = []*x509.Certificate{strangerCert(t)} }},
		{"a descriptor twice", p.key, func(o *dsig.SignOptions) { o.X509Descriptors = []dsig.X509Descriptor{dsig.X509SKI, dsig.X509SKI} }},
		{"unknown descriptor", p.key, func(o *dsig.SignOptions) { o.X509Descriptors = []dsig.X509Descriptor{99} }},
		{"SKI of a certificate without one", xmlsec.KeyProvider{Signer: rsaKey, Certificate: &noSKI}, func(o *dsig.SignOptions) { o.X509Descriptors = []dsig.X509Descriptor{dsig.X509SKI} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := signPKI(t, c.key, c.set); err == nil {
				t.Fatal("signed")
			}
		})
	}
}

// XML-DSig 3.2.2: with the key pinned, ds:KeyInfo is a hint, and a
// ds:X509Certificate Go cannot parse is not used, so it does not fail the
// signature; without a pinned key it is malformed (audit A5).
func TestX509CertificateUnparsableWhenPinned(t *testing.T) {
	cert := newKey(t, rsaKey).Certificate
	for _, bad := range []string{"AAAA", b64(cert.Raw[:len(cert.Raw)-1])} {
		doc, sig := signedCovDoc(t, covKI(`<ds:X509Data><ds:X509Certificate>`+bad+`</ds:X509Certificate></ds:X509Data>`))
		if _, err := dsig.Verify(doc, sig, dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("not pinned: %v", err)
		}
		for name, opts := range map[string]dsig.VerifyOptions{
			"Certificate": {Certificate: cert},
			"PublicKey":   {PublicKey: &rsaKey.PublicKey},
		} {
			cov, err := dsig.Verify(doc, sig, opts)
			if err != nil {
				t.Fatalf("%s pinned: %v", name, err)
			}
			if cov.KeyInfoForm != dsig.KeyInfoNone || len(cov.Intermediates) != 0 {
				t.Fatalf("%s pinned: coverage %+v", name, cov)
			}
		}
	}
}

// XML-DSig 4.5.4: a signing certificate and its re-issue, for the same key,
// are one leaf in any order: the first is the signing certificate and the
// other an intermediate. Leaves for different keys stay refused.
func TestX509DataReissuedCertificate(t *testing.T) {
	p := newPKI(t)
	reissued := newPKI(t).leaf // another chain, the same key
	doc, sig := signedCovDoc(t, covKI(`<ds:X509Data>`+x509Cert(reissued)+`</ds:X509Data><ds:X509Data>`+x509Cert(p.leaf)+`</ds:X509Data>`))
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Certificate.Equal(reissued) || len(cov.Intermediates) != 1 || !cov.Intermediates[0].Equal(p.leaf) {
		t.Fatalf("coverage %+v", cov)
	}
	// Sign accepts the re-issue in the chain it emits.
	if _, err := signPKI(t, p.key, func(o *dsig.SignOptions) { o.Chain = []*x509.Certificate{reissued, p.inter} }); err != nil {
		t.Fatal(err)
	}
}
