//go:build interop

package interop

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
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

// WSS4J processes a message signed, then encrypted, by this library, in the
// order the calls are natural to make: timestamp, the signer's token, sign
// the body and timestamp, Prepend the signature; then name the recipient's
// key, Prepend the EncryptedKey, encrypt the payload. The header comes out
// in WS-Security's order, [Timestamp, (recipient token,) EncryptedKey, signer
// token, Signature], and WSS4J, which processes the header in document
// order with Basic Security Profile enforcement on, must decrypt the body
// and then verify the signature over the plaintext. The recipient's key is
// named by a direct reference to its token, by its SubjectKeyIdentifier and
// by issuer and serial number. With encryptSignature, the signature is
// encrypted too, under the same EncryptedKey. The control appends the
// EncryptedKey instead, as this library's documentation used to say: WSS4J
// then verifies before decrypting, and must refuse.
func TestWSS4JProcessesSignThenEncrypt(t *testing.T) {
	for _, c := range []struct {
		name             string
		keyRef           string
		encryptSignature bool
		appendControl    bool
	}{
		{"token reference", "bst", false, false},
		{"key identifier", "ski", false, false},
		{"issuer serial", "issuer-serial", false, false},
		{"encrypted signature", "ski", true, false},
		{"control: EncryptedKey appended", "ski", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			signer, recipient := newKeypair(t, rsaKey(t)), newKeypair(t, rsaKey(t))
			doc := parse(t, []byte(envelope))
			body := xmltree.DocumentElement(doc).ChildElements()[1]
			payload := body.ChildElements()[0]

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
			signerTok, err := hdr.AddBinarySecurityToken(signer.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3)
			if err != nil {
				t.Fatal(err)
			}
			exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
			sig, err := dsig.Sign(doc, signer.provider, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References: []dsig.Reference{
					{URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
					{URI: "#" + tsID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
				},
				KeyInfo:         dsig.KeyInfoSecurityTokenReference,
				SecurityTokenID: signerTok,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := hdr.Prepend(sig); err != nil {
				t.Fatal(err)
			}

			var str *xdm.Node
			switch c.keyRef {
			case "bst":
				var tok string
				if tok, err = hdr.AddBinarySecurityToken(recipient.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3); err == nil {
					str, err = wss.NewSecurityTokenReference(doc, tok, "")
				}
			case "ski":
				str, err = wss.NewKeyIdentifierReference(recipient.provider.Certificate)
			case "issuer-serial":
				str, err = wss.NewIssuerSerialReference(recipient.provider.Certificate)
			}
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
			defer clear(ek.SessionKey)
			if err := ek.SetKeyInfo(str); err != nil {
				t.Fatal(err)
			}
			ek.AddDataReference("ED-1")
			if c.encryptSignature {
				ek.AddDataReference("ED-2")
			}
			place := hdr.Prepend
			if c.appendControl {
				place = hdr.Append
			}
			if err := place(ek.Element); err != nil {
				t.Fatal(err)
			}
			wantOrder := []string{"Timestamp", "EncryptedKey", "BinarySecurityToken", "Signature"}
			switch {
			case c.keyRef == "bst":
				wantOrder = append([]string{"Timestamp", "BinarySecurityToken"}, wantOrder[1:]...)
			case c.appendControl:
				wantOrder = []string{"Timestamp", "BinarySecurityToken", "Signature", "EncryptedKey"}
			}
			var order []string
			for _, e := range hdr.Element().ChildElements() {
				order = append(order, e.Name.Local)
			}
			if !slices.Equal(order, wantOrder) {
				t.Fatalf("header order %v, want %v", order, wantOrder)
			}

			out, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
			if err != nil {
				t.Fatal(err)
			}
			if c.encryptSignature {
				// EncryptElement leaves doc as it was; encrypt the signature
				// in the output, under the same key.
				doc2 := parse(t, out)
				opts.DataID = "ED-2"
				if out, err = xenc.EncryptElement(doc2, find(doc2, dsig.NSDSig, "Signature"), ek.SessionKey, opts); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(out), "SignatureValue") {
					t.Fatal("signature not encrypted")
				}
			}
			if strings.Contains(string(out), ">hello<") {
				t.Fatal("payload not encrypted")
			}

			res, err := santuario(t, "wss4j-process", tempFile(t, "soap.xml", out), recipient.keyPEM, recipient.certPEM, signer.certPEM)
			if c.appendControl {
				if err == nil {
					t.Fatalf("WSS4J accepted a header out of processing order:\n%s", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("WSS4J refused the message: %v\n%s\n%s", err, res, out)
			}
			// 4 is decryption, 2 a signature, 32 a timestamp.
			// WSS4J names a decrypted EncryptedData by its Id, without '#'.
			for _, want := range []string{"action 4\n", "action 2\n", "action 32\n", "decrypted ED-1\n",
				"signed #" + bodyID + "\n", "signed #" + tsID + "\n", ">hello</p:Payload>"} {
				if !strings.Contains(string(res), want) {
					t.Errorf("WSS4J output lacks %q:\n%s", strings.TrimSpace(want), res)
				}
			}
			if c.encryptSignature && !strings.Contains(string(res), "decrypted ED-2\n") {
				t.Errorf("WSS4J did not decrypt the signature:\n%s", res)
			}
			// WSS4J processes the header in document order and lists its
			// results newest first (each is added at index 0): the timestamp
			// last, then decryption, then verification. Decryption came
			// first, so the header was in processing order.
			r := string(res)
			if ts, d, s := strings.Index(r, "action 32\n"), strings.Index(r, "action 4\n"), strings.Index(r, "action 2\n"); !(s < d && d < ts) {
				t.Errorf("WSS4J did not process timestamp, decryption, signature in that order:\n%s", res)
			}
		})
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
