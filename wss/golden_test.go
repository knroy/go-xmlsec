// Golden files: the byte-exact output of whole signed and encrypted
// documents, kept in testdata/golden.
//
// A golden changes only when serialization changes, and a serialization
// change is exactly what breaks a peer silently while every round-trip test
// still passes. So the rule is:
//
//   - Regenerate only with -update, and only for this package:
//
//     go test ./wss -run TestGolden -update
//
//   - Review the diff (git diff wss/testdata/golden) before committing, and
//     say in the commit message why the octets changed. An unexplained golden
//     change is a bug, not a fixture refresh.
//
// The tests live here, in package wss_test, because generated wsu:Id values
// come from wss's unexported randReader, and the SetRandReader helper in
// export_test.go is visible only to test packages in this directory. dsig
// and xenc are imported from here; dsig's own tests cannot reach it.
//
// What makes the octets reproducible:
//
//   - A fixed RSA key and self-signed certificate, testdata/golden-key.pem,
//     test-only and committed on purpose. RSA PKCS#1 v1.5 signing is
//     deterministic, so every DigestValue and SignatureValue is fixed.
//   - wsu:Id values read from a fixed byte stream through SetRandReader.
//   - No clock: no timestamp is added, and certificate validity is not
//     checked on verification.
//   - AES-GCM (random IV) and RSA-OAEP (random padding) are not
//     deterministic, and neither is the session key, so the encrypted golden
//     masks every xenc:CipherValue and the decrypted plaintext has its own
//     golden.
//
// .gitattributes pins testdata/golden to LF on every OS.
package wss_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

var update = flag.Bool("update", false, "rewrite testdata/golden; review the diff before committing")

// checkGolden compares got with testdata/golden/name, or rewrites the file
// under -update.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s; review the diff before committing", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (create it with: go test ./wss -run %s -update)", err, t.Name())
	}
	if bytes.Equal(got, want) {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	t.Errorf("%s: output differs from the golden at byte %d (got %d bytes, golden %d)\n"+
		"  golden: %q\n  got:    %q\n"+
		"If the change is intended, run: go test ./wss -run %s -update\n"+
		"then review git diff wss/%s and explain the change in the commit.",
		path, i, len(got), len(want), excerpt(want, i), excerpt(got, i), t.Name(), filepath.ToSlash(path))
}

// excerpt returns b around offset i.
func excerpt(b []byte, i int) string {
	lo, hi := max(i-40, 0), min(i+40, len(b))
	return string(b[lo:hi])
}

// goldenKey loads the committed test-only key and certificate.
func goldenKey(t *testing.T) (xmlsec.KeyProvider, *rsa.PrivateKey) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "golden-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var cert *x509.Certificate
	var priv *rsa.PrivateKey
	for blk, rest := pem.Decode(b); blk != nil; blk, rest = pem.Decode(rest) {
		switch blk.Type {
		case "CERTIFICATE":
			cert, err = x509.ParseCertificate(blk.Bytes)
		case "PRIVATE KEY":
			var k any
			k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
			priv, _ = k.(*rsa.PrivateKey)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if cert == nil || priv == nil {
		t.Fatal("golden-key.pem: need a CERTIFICATE and an RSA PRIVATE KEY")
	}
	return xmlsec.KeyProvider{Signer: priv, Certificate: cert}, priv
}

// fixedIDs makes generated wsu:Id values id-0101..., id-0202..., and so on.
func fixedIDs(t *testing.T) {
	var b []byte
	for i := 1; i <= 16; i++ {
		b = append(b, bytes.Repeat([]byte{byte(i)}, 16)...)
	}
	wss.SetRandReader(t, bytes.NewReader(b))
}

func parseDoc(t *testing.T, b []byte) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return tree.Root
}

func mustFind(t *testing.T, doc *xdm.Node, ns, local string) *xdm.Node {
	t.Helper()
	var found *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if found == nil && e.IsElement(ns, local) {
			found = e
		}
	})
	if found == nil {
		t.Fatalf("no %s element", local)
	}
	return found
}

// The whitespace between elements is kept on purpose: it must survive
// signing, and it makes the golden diffable line by line.
const goldenEnvelope = `<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:eb="urn:example:eb">
<S:Header>
<eb:Messaging><eb:MessageId>m1@example.com</eb:MessageId></eb:Messaging>
</S:Header>
<S:Body><p:Payload xmlns:p="urn:example:p">hello</p:Payload></S:Body>
</S:Envelope>`

func goldenAttachments(t *testing.T) xmlsec.AttachmentSet {
	t.Helper()
	s, err := xmlsec.NewAttachmentSet(
		// Real parts always carry a Content-Type, and it decides the SwA
		// content canonicalization: text gets CRLF line endings, a gzip
		// payload is digested as its raw octets.
		&xmlsec.Attachment{ID: "att-1@example.com", Body: []byte("first attachment\n"),
			MIMEHeaders: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}}},
		&xmlsec.Attachment{ID: "att-2@example.com", Body: []byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0x00, 0x0a, 0x0d},
			MIMEHeaders: map[string][]string{"Content-Type": {"application/gzip"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type signedEnvelope struct {
	doc                  *xdm.Node
	hdr                  *wss.Header
	key                  xmlsec.KeyProvider
	priv                 *rsa.PrivateKey
	msgID, bodyID, tokID string
	body                 *xdm.Node
	atts                 xmlsec.AttachmentSet
}

// signGoldenEnvelope signs the messaging header, the body and both
// attachments into a WS-Security header, as an AS4 sender does.
func signGoldenEnvelope(t *testing.T) signedEnvelope {
	t.Helper()
	fixedIDs(t)
	s := signedEnvelope{doc: parseDoc(t, []byte(goldenEnvelope)), atts: goldenAttachments(t)}
	s.key, s.priv = goldenKey(t)
	s.body = mustFind(t, s.doc, wss.NSSOAP12, "Body")
	var err error
	if s.msgID, err = wss.AssignID(s.doc, mustFind(t, s.doc, "urn:example:eb", "Messaging")); err != nil {
		t.Fatal(err)
	}
	if s.bodyID, err = wss.AssignID(s.doc, s.body); err != nil {
		t.Fatal(err)
	}
	if s.hdr, err = wss.NewHeader(s.doc, wss.NSSOAP12, "", true); err != nil {
		t.Fatal(err)
	}
	if s.tokID, err = s.hdr.AddBinarySecurityToken(s.key.Certificate, nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	aco := []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}}
	sig, err := dsig.Sign(s.doc, s.key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + s.msgID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + s.bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "cid:att-1@example.com", Transforms: aco, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "cid:att-2@example.com", Transforms: aco, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: s.tokID,
		Attachments:     s.atts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	return s
}

// verifyGoldenEnvelope checks that a received envelope verifies against the
// golden key and covers everything signGoldenEnvelope signed. A golden that
// does not verify would be a wrong golden.
func verifyGoldenEnvelope(t *testing.T, received []byte, s signedEnvelope) {
	t.Helper()
	doc := parseDoc(t, received)
	cov, err := dsig.Verify(doc, mustFind(t, doc, dsig.NSDSig, "Signature"), dsig.VerifyOptions{
		Certificate:                       s.key.Certificate,
		AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
		AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
		Attachments:                       s.atts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.Covers(s.msgID, s.bodyID) || !cov.CoversAttachments("att-1@example.com", "att-2@example.com") ||
		cov.KeyInfoForm != dsig.KeyInfoSecurityTokenReference {
		t.Fatalf("coverage %+v", cov)
	}
}

// A signed SOAP 1.2 envelope with two attachments: binary security token,
// signature over the messaging header, the body and both attachments by
// cid: with Attachment-Content-Only, exclusive C14N, RSA-SHA256, KeyInfo as
// a SecurityTokenReference.
func TestGoldenSignedEnvelopeTwoAttachments(t *testing.T) {
	s := signGoldenEnvelope(t)
	out, err := c14n.Bytes(s.doc, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		t.Fatal(err)
	}
	verifyGoldenEnvelope(t, out, s)
	checkGolden(t, "signed-envelope-two-attachments.xml", out)
}

var (
	cipherValueRE   = regexp.MustCompile(`(<xenc:CipherValue>)[^<]*(</xenc:CipherValue>)`)
	encryptedDataRE = regexp.MustCompile(`<xenc:EncryptedData[ >][^\x00]*?</xenc:EncryptedData>`)
)

// The signed envelope, then encrypted: the body payload becomes an
// xenc:EncryptedData, AES-128-GCM, and the header gains an xenc:EncryptedKey,
// RSA-OAEP with explicit SHA-256 MGF and digest, naming the recipient's
// token and the EncryptedData. Ciphertext is random, so the golden is the
// envelope with every CipherValue masked, plus the decrypted plaintext; and
// the decrypted envelope must verify.
func TestGoldenSignedEncryptedEnvelope(t *testing.T) {
	s := signGoldenEnvelope(t)
	opts := xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm:          xmlsec.MGF1SHA256,
		DigestAlgorithm:       xmlsec.DigestSHA256,
		Recipient:             s.key.Certificate, // the test key is both sender and recipient
		DataID:                "ED-1",
	}
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ek.SessionKey)
	str, err := wss.NewSecurityTokenReference(s.doc, s.tokID, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.SetKeyInfo(str); err != nil {
		t.Fatal(err)
	}
	ek.AddDataReference(opts.DataID)
	if err := s.hdr.Append(ek.Element); err != nil {
		t.Fatal(err)
	}
	out, err := xenc.EncryptElement(s.doc, s.body.ChildElements()[0], ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(cipherValueRE.FindAll(out, -1)); n != 2 {
		t.Fatalf("%d CipherValues, want 2 (EncryptedKey and EncryptedData)", n)
	}
	checkGolden(t, "signed-encrypted-envelope.masked.xml", cipherValueRE.ReplaceAll(out, []byte("${1}MASKED${2}")))

	// As the receiver: unwrap the session key, decrypt, restore, verify.
	doc := parseDoc(t, out)
	key, err := xenc.DecryptEncryptedKey(mustFind(t, doc, xenc.NSXEnc, "EncryptedKey"), s.priv,
		[]string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := xenc.DecryptData(mustFind(t, doc, xenc.NSXEnc, "EncryptedData"), key, []string{xmlsec.EncAES128GCM})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "signed-encrypted-payload.xml", plain)

	if len(encryptedDataRE.FindAll(out, -1)) != 1 {
		t.Fatal("expected exactly one EncryptedData")
	}
	verifyGoldenEnvelope(t, encryptedDataRE.ReplaceAllLiteral(out, plain), s)
}

// signEnvelopedGolden signs src whole with an enveloped signature, KeyInfo
// X509Data, and checks the result against its golden.
func signEnvelopedGolden(t *testing.T, name, src string, alg c14n.Algorithm) {
	t.Helper()
	key, _ := goldenKey(t)
	signed, err := dsig.SignEnveloped(parseDoc(t, []byte(src)), key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(alg),
		References: []dsig.Reference{{
			URI:             "",
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: string(alg)},
			},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := parseDoc(t, signed)
	cov, err := dsig.Verify(doc, mustFind(t, doc, dsig.NSDSig, "Signature"), dsig.VerifyOptions{
		Certificate:                       key.Certificate,
		AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
		AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
		AllowedCanonicalizationAlgorithms: []string{string(alg)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cov.WholeDocumentSigned || cov.KeyInfoForm != dsig.KeyInfoX509Data {
		t.Fatalf("coverage %+v", cov)
	}
	checkGolden(t, name, signed)
}

// An enveloped signed metadata document: inclusive C14N, KeyInfo X509Data.
// The unused namespace and the comment are what inclusive canonicalization
// and the with-comments output must carry through unchanged.
func TestGoldenEnvelopedMetadata(t *testing.T) {
	signEnvelopedGolden(t, "enveloped-metadata.xml", `<smp:SignedServiceMetadata xmlns:smp="urn:example:smp" xmlns:unused="urn:example:unused">
<smp:ServiceMetadata><smp:Endpoint>https://example.com/</smp:Endpoint></smp:ServiceMetadata>
<!-- comment -->
</smp:SignedServiceMetadata>`, c14n.Inclusive10)
}

// The document of dsig's Example_enveloped, the README quick start, signed
// with the golden key: exclusive C14N, KeyInfo X509Data.
func TestGoldenEnvelopedInvoice(t *testing.T) {
	signEnvelopedGolden(t, "enveloped-invoice.xml", `<Invoice><Total>100.00</Total></Invoice>`, c14n.Exclusive10)
}
