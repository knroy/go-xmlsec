package wss_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/wss"
)

// signReproducibly signs the full AS4 shape, a BinarySecurityToken referenced
// from the signature's KeyInfo, a timestamp, the messaging header, the body
// and an attachment, with every ID and the clock supplied by the caller and
// nothing read from randReader. RSA PKCS#1 v1.5 is deterministic, so the
// output depends on the inputs alone.
func signReproducibly(t *testing.T) []byte {
	t.Helper()
	doc := parseDoc(t, []byte(goldenEnvelope))
	key, _ := goldenKey(t)
	step := func(_ string, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	step(wss.AssignIDWith(doc, mustFind(t, doc, "urn:example:eb", "Messaging"), "msg-1"))
	step(wss.AssignIDWith(doc, mustFind(t, doc, xmlsec.NSSOAP12, "Body"), "body-1"))
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	step(hdr.AddTimestampWithID(time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), 5*time.Minute, "ts-1"))
	step(hdr.AddBinarySecurityTokenWithID(key.Certificate, nil, xmlsec.BSTValueTypeX509v3, "bst-1"))
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#ts-1", Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#msg-1", Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#body-1", Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentSignature}}},
		},
		KeyInfo:          dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID:  "bst-1",
		SignatureID:      "sig-1",
		SignedInfoID:     "si-1",
		SignatureValueID: "sv-1",
		KeyInfoID:        "ki-1",
		Attachments:      goldenAttachments(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(sig); err != nil {
		t.Fatal(err)
	}
	b, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// With every ID supplied, the AS4 shape is byte-identical from run to run,
// with no test hook: a caller can build golden files and differentials on
// it.
func TestReproducibleAS4Signature(t *testing.T) {
	first := signReproducibly(t)
	for i := 1; i < 25; i++ {
		if got := signReproducibly(t); !bytes.Equal(got, first) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
	for _, want := range []string{`wsu:Id="bst-1"`, `wsu:Id="ts-1"`, `Id="sig-1"`, `URI="#bst-1"`} {
		if !bytes.Contains(first, []byte(want)) {
			t.Fatalf("no %s in\n%s", want, first)
		}
	}
	doc := parseDoc(t, first)
	key, _ := goldenKey(t)
	cov, err := dsig.Verify(doc, mustFind(t, doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
		Certificate: key.Certificate, Attachments: goldenAttachments(t)})
	if err != nil || !cov.Covers("ts-1", "msg-1", "body-1") || !cov.CoversAttachments("att-1@example.com") {
		t.Fatalf("the reproducible message does not verify: %v", err)
	}
}
