//go:build interop

package interop

import (
	"crypto"
	"strings"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// tokenTypeEncryptedKey is the ValueType and TokenType of a reference to an
// xenc:EncryptedKey (SOAP Message Security 1.1.1 section 7.7, BSP R3069).
const tokenTypeEncryptedKey = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey"

// WSS4J processes this library's symmetric-binding encryption, with Basic
// Security Profile enforcement on: an RSA-OAEP EncryptedKey without a
// ReferenceList, then a header ReferenceList naming the Body content's
// EncryptedData and an EncryptedHeader's, each EncryptedData naming the
// EncryptedKey by a SecurityTokenReference (EncryptOptions.DataKeyInfo).
func TestWSS4JProcessesOurSymmetricEncryption(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	doc := parse(t, []byte(envelope))
	hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	opts := encOpts
	opts.Recipient = recipient.provider.Certificate
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ek.SessionKey)
	ekID, err := wss.AssignID(doc, ek.Element)
	if err != nil {
		t.Fatal(err)
	}
	recip, err := wss.NewIssuerSerialReference(recipient.provider.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := ek.SetKeyInfo(recip); err != nil {
		t.Fatal(err)
	}
	if opts.DataKeyInfo, err = wss.NewSecurityTokenReference(doc, ekID, tokenTypeEncryptedKey); err != nil {
		t.Fatal(err)
	}
	list, err := wss.NewReferenceList("ED-body", "ED-header")
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(list); err != nil {
		t.Fatal(err)
	}
	if err := hdr.Prepend(ek.Element); err != nil {
		t.Fatal(err)
	}
	opts.DataID = "ED-body"
	out, err := xenc.EncryptContent(doc, xmltree.DocumentElement(doc).ChildElements()[1], ek.SessionKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	doc = parse(t, out)
	opts.DataID = "ED-header"
	if out, err = xenc.EncryptHeader(doc, find(doc, "urn:example:eb", "Messaging"), find(doc, xmlsec.NSWSSE, "Security"), ek.SessionKey, opts); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ">hello<") || strings.Contains(string(out), ">m1<") {
		t.Fatalf("not encrypted:\n%s", out)
	}

	res, err := santuario(t, "wss4j-process", tempFile(t, "soap.xml", out), recipient.keyPEM, recipient.certPEM, recipient.certPEM)
	if err != nil {
		t.Fatalf("WSS4J refused the message: %v\n%s\n%s", err, res, out)
	}
	for _, want := range []string{"action 4\n", "decrypted ED-body\n", "decrypted ED-header\n", ">hello</p:Payload>", "<eb:MessageId>m1</eb:MessageId>"} {
		if !strings.Contains(string(res), want) {
			t.Errorf("WSS4J output lacks %q:\n%s", strings.TrimSpace(want), res)
		}
	}
}

// This library decrypts WSS4J's symmetric-binding encryption under
// DecryptOptions.StrictBSP: the header ReferenceList gives the
// EncryptedData (ReferencedData), each names the EncryptedKey by a
// SecurityTokenReference (FindEncryptedKey), and the EncryptedHeader is
// replaced by its header block (DecryptHeader).
func TestWeDecryptWSS4JSymmetricEncryption(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	outPath := tempFile(t, "out.xml", nil)
	mustSantuario(t, "wss4j-encrypt-symmetric", tempFile(t, "soap.xml", []byte(envelope)), recipient.certPEM, "{urn:example:eb}Messaging", outPath)
	raw := readFile(t, outPath)
	doc := parse(t, raw)
	sec := find(doc, xmlsec.NSWSSE, "Security")
	kids := sec.ChildElements()
	if len(kids) != 2 || !kids[0].IsElement(xmlsec.NSXEnc, "EncryptedKey") || !kids[1].IsElement(xmlsec.NSXEnc, "ReferenceList") ||
		find(kids[0], xmlsec.NSXEnc, "ReferenceList") != nil {
		t.Fatalf("not the symmetric shape:\n%s", raw)
	}
	eds, err := xenc.ReferencedData(kids[1])
	if err != nil || len(eds) != 2 {
		t.Fatalf("%d, %v\n%s", len(eds), err, raw)
	}
	strict := xenc.DecryptOptions{StrictBSP: true}
	var header, body bool
	for _, ed := range eds {
		ek, err := xenc.FindEncryptedKey(ed)
		if err != nil {
			t.Fatal(err)
		}
		key, err := xenc.DecryptEncryptedKey(ek, recipient.provider.Signer.(crypto.Decrypter), strict)
		if err != nil {
			t.Fatal(err)
		}
		if ed.Parent.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
			out, err := xenc.DecryptHeader(doc, ed.Parent, key, strict)
			if err != nil || !strings.Contains(string(out), "<eb:MessageId>m1</eb:MessageId></eb:Messaging>") {
				t.Fatalf("header: %v\n%s", err, out)
			}
			header = true
			continue
		}
		pt, err := xenc.DecryptData(ed, key, strict)
		if err != nil || !strings.Contains(string(pt), ">hello</p:Payload>") {
			t.Fatalf("body: %v\n%s", err, pt)
		}
		body = true
	}
	if !header || !body {
		t.Fatalf("header %v, body %v\n%s", header, body, raw)
	}
}
