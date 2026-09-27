//go:build interop

package interop

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// The XML Signature 1.1 structures beyond ds:SignedInfo: ds:Object in an
// enveloping signature, ds:SignatureProperties, ds:Manifest, the
// InclusiveNamespaces PrefixList of ds:CanonicalizationMethod and HMAC
// generation, each checked against Santuario, and xmlsec1 where it applies.

var excRef = []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}

func objRef(uri string) dsig.Reference {
	return dsig.Reference{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256, Transforms: excRef}
}

func children(t *testing.T, s string) []*xdm.Node {
	t.Helper()
	return xmltree.DocumentElement(parse(t, []byte(s))).Children
}

func bytesOf(t *testing.T, doc *xdm.Node) []byte {
	t.Helper()
	b, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Santuario and xmlsec1 accept our enveloping signature over its ds:Object,
// a ds:SignatureProperty and its ds:KeyInfo.
func TestPeersVerifyOurEnvelopingSignature(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	sig, err := dsig.Sign(nil, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		KeyInfo:                   dsig.KeyInfoX509Data,
		SignatureID:               "sig",
		KeyInfoID:                 "ki",
		References:                []dsig.Reference{objRef("#obj"), objRef("#prop"), objRef("#ki")},
		Objects:                   []dsig.Object{{ID: "obj", Content: children(t, `<r xmlns:p="urn:example:p"><p:data>hello</p:data></r>`)}},
		Properties: []dsig.SignatureProperty{{ID: "prop",
			Content: children(t, `<r xmlns:t="urn:example:t"><t:time>2026-09-26</t:time></r>`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := &xdm.Node{Kind: xdm.KindDocument}
	doc.AppendChild(sig)
	signed := bytesOf(t, doc)
	tampered := bytes.Replace(signed, []byte("hello"), []byte("jello"), 1)

	mustSantuario(t, "--id-attr", "Id", "verify", tempFile(t, "signed.xml", signed), kp.certPEM)
	if out, err := santuario(t, "--id-attr", "Id", "verify", tempFile(t, "tampered.xml", tampered), kp.certPEM); err == nil {
		t.Fatalf("Santuario accepted a tampered Object:\n%s", out)
	}
	run(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "signed.xml", signed))
	if out, err := runErr(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "tampered.xml", tampered)); err == nil {
		t.Fatalf("xmlsec1 accepted a tampered Object:\n%s", out)
	}
}

// We accept Santuario's enveloping signature, with no ID attribute named:
// the Ids of its own ds:Object and ds:SignatureProperty count.
func TestWeVerifySantuarioEnvelopingSignature(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-enveloping", kp.keyPEM, kp.certPEM, out)
	signed := readFile(t, out)
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: kp.provider.Certificate})
	if err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
	if !slices.Equal(cov.SignedElementIDs, []string{"obj", "prop"}) {
		t.Fatalf("coverage %v", cov.SignedElementIDs)
	}
}

const manifestInput = `<r><a xml:id="a">hello</a></r>`

// Santuario accepts our signature over a ds:Manifest, and refuses it once
// the Manifest changes; and the Manifest's reference digests exactly as
// Santuario's own does, for the same input. (Santuario follows a Manifest
// only through a reference that ends in a node set, which Sign never
// produces: behind a canonicalization it reparses the Manifest alone, and
// then cannot resolve #a.)
func TestSantuarioVerifiesOurManifest(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(manifestInput))
	m, err := dsig.BuildManifest(doc, []dsig.Reference{objRef("#a")}, dsig.SignOptions{ManifestID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	r := objRef("#m")
	r.Type = xmlsec.TypeManifest
	if _, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		KeyInfo:                   dsig.KeyInfoX509Data,
		References:                []dsig.Reference{r},
		Objects:                   []dsig.Object{{Content: []*xdm.Node{m}}},
		Parent:                    xmltree.DocumentElement(doc),
	}); err != nil {
		t.Fatal(err)
	}
	signed := bytesOf(t, doc)
	mustSantuario(t, "--id-attr", "Id", "verify", tempFile(t, "signed.xml", signed), kp.certPEM)
	ours := manifestDigest(t, signed)
	// The Manifest's DigestValue, the last in the document.
	i := bytes.LastIndex(signed, []byte("<ds:DigestValue>")) + len("<ds:DigestValue>")
	changed := tempFile(t, "changed.xml", slices.Concat(signed[:i], []byte("AAAA"), signed[i:]))
	if out, err := santuario(t, "--id-attr", "Id", "verify", changed, kp.certPEM); err == nil {
		t.Fatalf("Santuario accepted a changed Manifest:\n%s", out)
	}

	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-manifest", tempFile(t, "in.xml", []byte(manifestInput)), kp.keyPEM, kp.certPEM, out)
	if theirs := manifestDigest(t, readFile(t, out)); !bytes.Equal(ours, theirs) {
		t.Fatalf("Manifest reference digest differs: ours %x, Santuario %x", ours, theirs)
	}
}

// manifestDigest returns the DigestValue of the first reference of the
// ds:Manifest in doc.
func manifestDigest(t *testing.T, doc []byte) []byte {
	t.Helper()
	m := find(parse(t, doc), xmlsec.NSDSig, "Manifest")
	return mustBase64(t, find(m, xmlsec.NSDSig, "DigestValue"))
}

// We verify Santuario's Manifest: the signature covers it, and
// VerifyManifest reports what its reference covers.
func TestWeVerifySantuarioManifest(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	out := filepath.Join(t.TempDir(), "out.xml")
	mustSantuario(t, "sign-manifest", tempFile(t, "in.xml", []byte(manifestInput)), kp.keyPEM, kp.certPEM, out)
	signed := readFile(t, out)
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{Certificate: kp.provider.Certificate})
	if err != nil {
		t.Fatalf("%v\n%s", err, signed)
	}
	mcov, err := dsig.VerifyManifest(doc, find(doc, xmlsec.NSDSig, "Manifest"), cov, dsig.VerifyOptions{})
	if err != nil || !mcov.Covers("a") {
		t.Fatalf("VerifyManifest: %v\n%s", err, signed)
	}
}

// Santuario and xmlsec1 apply the PrefixList of our
// ds:CanonicalizationMethod: the signature verifies, and fails once the
// listed, in-scope but unused binding changes.
func TestPeersVerifyOurCanonicalizationPrefixes(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(`<r xmlns:p="urn:example:p"><a xml:id="a">x</a></r>`))
	if _, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		CanonicalizationPrefixes:  []string{"p"},
		KeyInfo:                   dsig.KeyInfoX509Data,
		References:                []dsig.Reference{objRef("#a")},
		Parent:                    xmltree.DocumentElement(doc),
	}); err != nil {
		t.Fatal(err)
	}
	signed := bytesOf(t, doc)
	if !bytes.Contains(signed, []byte(`PrefixList="p"`)) {
		t.Fatalf("no PrefixList:\n%s", signed)
	}
	rebound := tempFile(t, "rebound.xml", bytes.Replace(signed, []byte(`"urn:example:p"`), []byte(`"urn:example:q"`), 1))
	mustSantuario(t, "verify", tempFile(t, "signed.xml", signed), kp.certPEM)
	if out, err := santuario(t, "verify", rebound, kp.certPEM); err == nil {
		t.Fatalf("Santuario ignored the PrefixList:\n%s", out)
	}
	run(t, "--verify", "--trusted-pem", kp.certPEM, tempFile(t, "signed.xml", signed))
	if out, err := runErr(t, "--verify", "--trusted-pem", kp.certPEM, rebound); err == nil {
		t.Fatalf("xmlsec1 ignored the PrefixList:\n%s", out)
	}
}

// Santuario accepts our HMAC-SHA256 signature with the shared secret, and
// only with it.
func TestSantuarioVerifiesOurHMAC(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), xmlsec.KeyProvider{}, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigHMACSHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		HMACKey:                   secret,
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, excRef[0]}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := tempFile(t, "signed.xml", signed)
	mustSantuario(t, "verify-hmac", doc, tempFile(t, "key.bin", secret))
	if out, err := santuario(t, "verify-hmac", doc, tempFile(t, "other.bin", bytes.Repeat([]byte("x"), 32))); err == nil {
		t.Fatalf("Santuario accepted another secret:\n%s", out)
	}
}
