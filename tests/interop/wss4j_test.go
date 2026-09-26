//go:build interop

package interop

import (
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// WSS4J, the WS-Security engine phase4 and most Java stacks are built on,
// processes a header built entirely by this library: a timestamp, a binary
// security token, and a signature over the body and the timestamp keyed by a
// direct SecurityTokenReference. Basic Security Profile enforcement stays
// on, so a header WSS4J would warn about fails here. Acceptance criterion 6.
func TestWSS4JProcessesOurSecurityHeader(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(envelope))
	body := xmltree.DocumentElement(doc).ChildElements()[1]

	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tsID, err := hdr.AddTimestamp(time.Now(), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(kp.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
	sig, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{
			{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
			{URI: "#" + tsID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
		},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tokenID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	signed, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}

	out, err := santuario(t, "wss4j-verify", tempFile(t, "soap.xml", signed), kp.certPEM)
	if err != nil {
		t.Fatalf("WSS4J refused the header: %v\n%s\n%s", err, out, signed)
	}
	// WSS4J's actions: 2 is a signature, 32 a timestamp, 4096 a binary
	// security token; it names each signed element by its "#id" reference.
	for _, want := range []string{"action 2\n", "action 32\n", "action 4096\n", "signed #" + bodyID + "\n", "signed #" + tsID + "\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("WSS4J output lacks %q:\n%s", strings.TrimSpace(want), out)
		}
	}
}

// WSS4J decrypts a message encrypted by this library, composed as a
// WS-Security sender does: the recipient's certificate as a binary security
// token, an EncryptedKey in the header naming it through a
// SecurityTokenReference, and a ReferenceList pointing at the EncryptedData
// that replaced the payload. Acceptance criterion 4.
func TestWSS4JDecryptsOurEncryption(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(envelope))
	payload := xmltree.DocumentElement(doc).ChildElements()[1].ChildElements()[0]

	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(recipient.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	opts := encOpts
	opts.Recipient = recipient.provider.Certificate
	opts.DataID = "ED-1"
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	str, err := wss.NewSecurityTokenReference(doc, tokenID, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.SetKeyInfo(str); err != nil {
		t.Fatal(err)
	}
	ek.AddDataReference(opts.DataID)
	if err := hdr.Append(ek.Element); err != nil {
		t.Fatal(err)
	}
	encrypted, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted), ">hello<") {
		t.Fatal("payload not encrypted")
	}

	out, err := santuario(t, "wss4j-decrypt", tempFile(t, "soap.xml", encrypted), recipient.keyPEM, recipient.certPEM)
	if err != nil {
		t.Fatalf("WSS4J could not decrypt: %v\n%s\n%s", err, out, encrypted)
	}
	// Action 4 is decryption.
	for _, want := range []string{"action 4\n", ">hello</p:Payload>"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("WSS4J output lacks %q:\n%s", want, out)
		}
	}
}
