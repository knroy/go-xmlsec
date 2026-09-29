//go:build interop

package interop

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// Canonical XML 1.1 differs from 1.0 only on a document subset: it does not
// inherit an ancestor's xml:id, and it joins the xml:base values of the
// omitted ancestors (C14N 1.1 section 2.4) instead of copying the nearest.
// Both documents sign t, whose ancestors carry xml:base, xml:lang,
// xml:space and xml:id.
const (
	// xmlBaseOneLevel has one omitted ancestor with an xml:base: t's
	// canonical xml:base is http://example.com/a/c/.
	xmlBaseOneLevel = `<r xml:base="http://example.com/a/" xml:lang="en" xml:id="r">` +
		`<m xml:space="preserve"><t xml:id="t" xml:base="c/">text</t></m></r>`

	// xmlBaseNested has two: t's canonical xml:base is
	// http://example.com/a/b/c/.
	xmlBaseNested = `<r xml:base="http://example.com/a/" xml:lang="en" xml:id="r">` +
		`<m xml:base="b/" xml:space="preserve"><t xml:id="t" xml:base="c/">text</t></m></r>`
)

// subsetReference is the one reference every side signs: t, through the
// enveloped-signature transform and alg.
func subsetReference(alg c14n.Algorithm) string {
	return `<ds:Reference URI="#t"><ds:Transforms>` +
		`<ds:Transform Algorithm="` + xmlsec.TransformEnvelopedSignature + `"/>` +
		`<ds:Transform Algorithm="` + string(alg) + `"/>` +
		`</ds:Transforms><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><ds:DigestValue/></ds:Reference>`
}

func signOurSubset(t *testing.T, kp keypair, doc string, alg c14n.Algorithm) []byte {
	t.Helper()
	signed, err := dsig.SignEnveloped(parse(t, []byte(doc)), kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(alg),
		References: []dsig.Reference{{URI: "#t", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(alg)}}}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func santuarioSubset(t *testing.T, kp keypair, doc string, alg c14n.Algorithm) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-enveloped", tempFile(t, "in.xml", []byte(doc)),
		kp.keyPEM, kp.certPEM, string(alg), xmlsec.SigRSASHA256, out, "#t")
	return readFile(t, out)
}

// xmlsec1Subset signs the same SignedInfo as signOurSubset from a template,
// so the SignatureValue is comparable too.
func xmlsec1Subset(t *testing.T, kp keypair, doc string, alg c14n.Algorithm) []byte {
	t.Helper()
	tmpl := strings.Replace(doc, "</r>", `<ds:Signature xmlns:ds="`+xmlsec.NSDSig+`"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="`+string(alg)+`"/>`+
		`<ds:SignatureMethod Algorithm="`+xmlsec.SigRSASHA256+`"/>`+subsetReference(alg)+
		`</ds:SignedInfo><ds:SignatureValue/>`+
		`<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo></ds:Signature></r>`, 1)
	out := filepath.Join(t.TempDir(), "out.xml")
	run(t, "--sign", "--privkey-pem", kp.keyPEM+","+kp.certPEM, "--output", out, tempFile(t, "tmpl.xml", []byte(tmpl)))
	signed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func firstDigest(t *testing.T, signed []byte) []byte {
	t.Helper()
	_, d := signatureValue(t, signed)
	if len(d) == 0 {
		t.Fatalf("no digest in\n%s", signed)
	}
	return d[0]
}

// The same subset signed by us, xmlsec1 and Santuario carries
// byte-identical digests and SignatureValue, and each side verifies the
// others', under Canonical XML 1.0 and 1.1; the nested xml:base case is the
// exception below.
func TestSubsetSignatureMatchesReferences(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	for _, c := range []struct {
		name string
		doc  string
		alg  c14n.Algorithm
	}{
		{"C14N 1.0, nested xml:base", xmlBaseNested, c14n.Inclusive10},
		{"C14N 1.1, one xml:base", xmlBaseOneLevel, c14n.Inclusive11},
		{"C14N 1.1, nested xml:base", xmlBaseNested, c14n.Inclusive11},
	} {
		t.Run(c.name, func(t *testing.T) {
			ours := signOurSubset(t, kp, c.doc, c.alg)
			compareSignatures(t, ours, xmlsec1Subset(t, kp, c.doc, c.alg))
			run(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "ours.xml", ours))
			if c.doc == xmlBaseNested && c.alg == c14n.Inclusive11 {
				return // Santuario differs: TestSantuarioC14N11NestedXMLBase
			}
			theirs := santuarioSubset(t, kp, c.doc, c.alg)
			compareSignatures(t, ours, theirs)
			mustSantuario(t, "verify", tempFile(t, "ours.xml", ours), kp.certPEM)
			doc := parse(t, theirs)
			cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
				Certificate:                       kp.provider.Certificate,
				AllowedCanonicalizationAlgorithms: []string{string(c.alg)},
			})
			if err != nil || !cov.Covers("t") {
				t.Fatalf("we refuse Santuario's signature: %v\n%s", err, theirs)
			}
		})
	}
	// The documents must exercise 1.1: it digests t unlike 1.0.
	if bytes.Equal(firstDigest(t, signOurSubset(t, kp, xmlBaseNested, c14n.Inclusive10)),
		firstDigest(t, signOurSubset(t, kp, xmlBaseNested, c14n.Inclusive11))) {
		t.Fatal("C14N 1.0 and 1.1 digest the subset alike")
	}
}

// A known Santuario divergence, kept visible so a fix upstream is noticed:
// with two omitted ancestors carrying xml:base, Santuario 4.0.4 joins only
// one of them, and digests xml:base="http://example.com/a/c/" where C14N 1.1
// section 2.4, this library and xmlsec1 give http://example.com/a/b/c/. It
// also writes that value into t in the document it outputs.
func TestSantuarioC14N11NestedXMLBase(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	theirs := santuarioSubset(t, kp, xmlBaseNested, c14n.Inclusive11)
	ours := firstDigest(t, signOurSubset(t, kp, xmlBaseNested, c14n.Inclusive11))
	if bytes.Equal(firstDigest(t, theirs), ours) {
		t.Fatal("Santuario now agrees with C14N 1.1 on nested xml:base: fold this case into TestSubsetSignatureMatchesReferences")
	}
	if !bytes.Contains(theirs, []byte(`xml:base="http://example.com/a/c/"`)) {
		t.Fatalf("Santuario diverges differently than recorded:\n%s", theirs)
	}
}
