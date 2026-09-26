//go:build interop

package interop

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
	"github.com/knroy/go-xmlsec/xenc"
)

// swaPart is an attachment as a MIME part: headers in wire order, then body.
type swaPart struct {
	headers [][2]string
	body    string
}

// swaParts exercise each content canonicalization of SwA profile 5.4.2 and
// the header rules of 5.4.1 that WSS4J applies: an XML body that
// canonicalizes differently from its octets, with a comment in
// Content-Description and a mixed-case filename; a text body with LF line
// endings; and a binary body, digested as is.
var swaParts = []swaPart{
	{[][2]string{
		{"Content-Type", "application/xml; charset=UTF-8"},
		{"Content-Transfer-Encoding", "binary"},
		{"Content-ID", "<invoice@example.com>"},
		{"Content-Description", "The invoice (draft)"},
		{"Content-Disposition", `attachment; filename="Invoice.XML"`},
	}, "<?xml version='1.0'?>\n<inv:Invoice xmlns:inv='urn:inv' xmlns:unused='urn:u'  b='1'>\n  <Total>100</Total><!-- c -->\n</inv:Invoice>\n"},
	{[][2]string{
		{"Content-Type", "text/plain; charset=us-ascii"},
		{"Content-ID", "<note@example.com>"},
	}, "line 1\nline 2\n"},
	{[][2]string{
		{"Content-Type", "application/octet-stream"},
		{"Content-ID", "<blob@example.com>"},
		{"Content-Location", "blob.bin"},
	}, "\x00\xff\n\r\x01"},
}

func (p swaPart) id() string {
	for _, h := range p.headers {
		if h[0] == "Content-ID" {
			return strings.Trim(h[1], "<>")
		}
	}
	return ""
}

func (p swaPart) attachment() *xmlsec.Attachment {
	a := &xmlsec.Attachment{ID: p.id(), Body: []byte(p.body), MIMEHeaders: map[string][]string{}}
	for _, h := range p.headers {
		a.MIMEHeaders[h[0]] = []string{h[1]}
	}
	return a
}

// file writes the part in the harness's part-file layout.
func (p swaPart) file(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, h := range p.headers {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	return tempFile(t, "part", []byte(b.String()+"\r\n"+p.body))
}

func swaSet(t *testing.T, parts []swaPart) xmlsec.AttachmentSet {
	t.Helper()
	var atts []*xmlsec.Attachment
	for _, p := range parts {
		atts = append(atts, p.attachment())
	}
	s, err := xmlsec.NewAttachmentSet(atts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func swaFiles(t *testing.T, parts []swaPart) []string {
	var files []string
	for _, p := range parts {
		files = append(files, p.file(t))
	}
	return files
}

// swaSigned returns an envelope whose WS-Security header signs each part by
// cid: with transform, keyed by a binary security token.
func swaSigned(t *testing.T, kp keypair, transform string) []byte {
	t.Helper()
	doc := parse(t, []byte(envelope))
	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", true)
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(kp.provider.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		t.Fatal(err)
	}
	var refs []dsig.Reference
	for _, p := range swaParts {
		refs = append(refs, dsig.Reference{URI: "cid:" + p.id(), DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: transform}}})
	}
	sig, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References:                refs,
		KeyInfo:                   dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID:           tokenID,
		Attachments:               swaSet(t, swaParts),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		t.Fatal(err)
	}
	b, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// WSS4J verifies attachment signatures made by this library with both SwA
// signature transforms, and rejects them when what the transform covers
// changes. It refuses the Attachment-Content-Only URI as a ds:Transform,
// which the profile defines only as an EncryptedData Type.
func TestWSS4JVerifiesOurAttachmentSignatures(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	for _, c := range []struct {
		transform string
		tamper    func(p *swaPart) // a change the transform must detect
	}{
		{xmlsec.TransformAttachmentContentSignature, func(p *swaPart) { p.body = strings.Replace(p.body, "100", "900", 1) }},
		{xmlsec.TransformAttachmentCompleteSignature, func(p *swaPart) { p.headers[3][1] = "The receipt" }},
	} {
		t.Run(c.transform[strings.Index(c.transform, "#")+1:], func(t *testing.T) {
			soap := tempFile(t, "soap.xml", swaSigned(t, kp, c.transform))
			out, err := santuario(t, append([]string{"wss4j-verify", soap, kp.certPEM}, swaFiles(t, swaParts)...)...)
			if err != nil {
				t.Fatalf("WSS4J refused the signature: %v\n%s", err, out)
			}
			for _, p := range swaParts {
				if want := "signed cid:" + p.id() + "\n"; !strings.Contains(string(out), want) {
					t.Errorf("WSS4J output lacks %q:\n%s", strings.TrimSpace(want), out)
				}
			}

			tampered := append([]swaPart(nil), swaParts...)
			tampered[0].headers = append([][2]string(nil), tampered[0].headers...)
			c.tamper(&tampered[0])
			if out, err := santuario(t, append([]string{"wss4j-verify", soap, kp.certPEM}, swaFiles(t, tampered)...)...); err == nil {
				t.Fatalf("WSS4J accepted a tampered attachment:\n%s", out)
			}
		})
	}

	// WSS4J refuses #Attachment-Content-Only as a signature transform: it is
	// an EncryptedData Type. That is why this library no longer signs or
	// verifies with it; TestSignErrors covers the refusal.
}

// This library verifies attachment signatures WSS4J makes with both SwA
// signature transforms.
func TestWeVerifyWSS4JAttachmentSignatures(t *testing.T) {
	kp := newKeypair(t, rsaKey(t))
	for modifier, transform := range map[string]string{
		"Content": xmlsec.TransformAttachmentContentSignature,
		"Element": xmlsec.TransformAttachmentCompleteSignature,
	} {
		t.Run(modifier, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "signed.xml")
			args := []string{"wss4j-sign-attachments", tempFile(t, "soap.xml", []byte(envelope)), kp.keyPEM, kp.certPEM, modifier, outPath}
			mustSantuario(t, append(args, swaFiles(t, swaParts)...)...)
			signed := readFile(t, outPath)

			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, find(doc, dsig.NSDSig, "Signature"), dsig.VerifyOptions{
				Certificate: kp.provider.Certificate,
				Attachments: swaSet(t, swaParts),
			})
			if err != nil {
				t.Fatalf("%v\n%s", err, signed)
			}
			for i, p := range swaParts {
				if !cov.CoversAttachments(p.id()) {
					t.Errorf("coverage lacks %s: %+v", p.id(), cov)
				}
				if got := cov.References[i].Transforms[0].Algorithm; got != transform {
					t.Errorf("WSS4J used transform %s", got)
				}
			}
		})
	}
}

// WSS4J decrypts attachments this library encrypts, content only and
// complete, with the EncryptedKey in the header naming the recipient's token
// and every EncryptedData. For Attachment-Complete it must recover the
// headers from the ciphertext.
func TestWSS4JDecryptsOurAttachmentEncryption(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	for _, typ := range []string{xmlsec.TransformAttachmentContentOnly, xmlsec.TransformAttachmentComplete} {
		t.Run(typ[strings.Index(typ, "#")+1:], func(t *testing.T) {
			doc := parse(t, []byte(envelope))
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
			var eds []*xdm.Node
			var files []string
			for i, p := range swaParts {
				opts.DataID = "ED-" + string(rune('1'+i))
				ct, ed, err := xenc.EncryptAttachment(p.attachment(), ek.SessionKey, typ, opts)
				if err != nil {
					t.Fatal(err)
				}
				if err := ek.AddDataReference(opts.DataID); err != nil {
					t.Fatal(err)
				}
				eds = append(eds, ed)
				files = append(files, swaPart{[][2]string{
					{"Content-ID", "<" + p.id() + ">"},
					{"Content-Type", "application/octet-stream"},
					{"Content-Transfer-Encoding", "binary"},
				}, string(ct)}.file(t))
			}
			for _, el := range append([]*xdm.Node{ek.Element}, eds...) {
				if err := hdr.Append(el); err != nil {
					t.Fatal(err)
				}
			}
			soap, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
			if err != nil {
				t.Fatal(err)
			}

			out, err := santuario(t, append([]string{"wss4j-decrypt", tempFile(t, "soap.xml", soap), recipient.keyPEM, recipient.certPEM}, files...)...)
			if err != nil {
				t.Fatalf("WSS4J could not decrypt: %v\n%s\n%s", err, out, soap)
			}
			got := map[string][]string{} // id -> mimeType, part file
			for _, line := range strings.Split(string(out), "\n") {
				if f := strings.SplitN(line, " ", 4); len(f) == 4 && f[0] == "attachment" {
					b, err := base64.StdEncoding.DecodeString(f[2])
					if err != nil {
						t.Fatal(err)
					}
					got[f[1]] = []string{f[3], string(b)}
				}
			}
			for _, p := range swaParts {
				g, ok := got[p.id()]
				if !ok {
					t.Fatalf("WSS4J returned no %s:\n%s", p.id(), out)
				}
				if !strings.HasSuffix(g[1], "\r\n\r\n"+p.body) {
					t.Errorf("%s: body %q", p.id(), g[1])
				}
				if typ == xmlsec.TransformAttachmentContentOnly {
					if g[0] != p.headers[0][1] {
						t.Errorf("%s: MimeType %q", p.id(), g[0])
					}
					continue
				}
				// The listed headers come back from the ciphertext; the outer
				// Content-Type is replaced.
				for _, h := range p.headers {
					if h[0] != "Content-Transfer-Encoding" && !strings.Contains(g[1], h[0]+": "+h[1]+"\r\n") {
						t.Errorf("%s: header %s not recovered:\n%q", p.id(), h[0], g[1])
					}
				}
			}
		})
	}
}

// This library decrypts attachments WSS4J encrypts, content only and
// complete.
func TestWeDecryptWSS4JAttachmentEncryption(t *testing.T) {
	recipient := newKeypair(t, rsaKey(t))
	for modifier, typ := range map[string]string{
		"Content": xmlsec.TransformAttachmentContentOnly,
		"Element": xmlsec.TransformAttachmentComplete,
	} {
		t.Run(modifier, func(t *testing.T) {
			dir := t.TempDir()
			outPath := filepath.Join(dir, "encrypted.xml")
			args := []string{"wss4j-encrypt-attachments", tempFile(t, "soap.xml", []byte(envelope)), recipient.certPEM, modifier, outPath, dir}
			mustSantuario(t, append(args, swaFiles(t, swaParts)...)...)
			doc := parse(t, readFile(t, outPath))

			key, err := xenc.DecryptEncryptedKey(find(doc, xenc.NSXEnc, "EncryptedKey"), recipient.provider.Decrypter,
				[]string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			xmltree.Walk(doc, func(ed *xdm.Node) {
				if !ed.IsElement(xenc.NSXEnc, "EncryptedData") {
					return
				}
				n++
				if ed.AttrValue("Type") != typ {
					t.Errorf("Type %q", ed.AttrValue("Type"))
				}
				ref := find(ed, xenc.NSXEnc, "CipherReference").AttrValue("URI")
				part := readFile(t, filepath.Join(dir, strings.TrimPrefix(ref, "cid:")))
				// WSS4J moves every listed header into an Attachment-Complete
				// ciphertext, so a part may have no headers at all.
				_, ct, _ := bytes.Cut(append([]byte("\r\n"), part...), []byte("\r\n\r\n"))
				att, err := xenc.DecryptAttachment(ed, ct, key, []string{xmlsec.EncAES128GCM})
				if err != nil {
					t.Fatalf("%s: %v", ref, err)
				}
				for _, p := range swaParts {
					if p.id() != att.ID {
						continue
					}
					if string(att.Body) != p.body {
						t.Errorf("%s: body %q", att.ID, att.Body)
					}
					for _, h := range p.headers {
						v := att.MIMEHeaders[h[0]]
						switch {
						case typ == xmlsec.TransformAttachmentContentOnly && h[0] == "Content-Type",
							typ == xmlsec.TransformAttachmentComplete && h[0] != "Content-Transfer-Encoding":
							if len(v) != 1 || v[0] != h[1] {
								t.Errorf("%s: %s is %q, want %q", att.ID, h[0], v, h[1])
							}
						}
					}
				}
			})
			if n != len(swaParts) {
				t.Fatalf("%d EncryptedData, want %d", n, len(swaParts))
			}
		})
	}
}
