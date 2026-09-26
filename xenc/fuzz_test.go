package xenc_test

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// fuzzOpts is as4Opts for fuzz setup, which has no *testing.T. Encryption
// reads only the recipient's public key, so no certificate is issued.
func fuzzOpts() xenc.EncryptOptions {
	return xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
		MGFAlgorithm:          xmlsec.MGF1SHA256,
		DigestAlgorithm:       xmlsec.DigestSHA256,
		Recipient:             &x509.Certificate{PublicKey: &recipientKey.PublicKey},
	}
}

// fuzzBytes serializes el as reparse does.
func fuzzBytes(el *xdm.Node) []byte {
	return must(c14n.Bytes(el, c14n.Options{Algorithm: c14n.Exclusive10}))
}

// fuzzFirst returns the first element named local, in any namespace, so that
// a mutated namespace still reaches the callee's own check.
func fuzzFirst(doc *xdm.Node, local string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(doc, func(e *xdm.Node) {
		if found == nil && e.Name.Local == local {
			found = e
		}
	})
	return found
}

func FuzzDecryptEncryptedKey(f *testing.F) {
	for _, label := range [][]byte{nil, []byte("label")} {
		opts := fuzzOpts()
		opts.OAEPParams = label
		f.Add(fuzzBytes(must(xenc.GenerateEncryptedKey(opts)).Element))
	}
	valid := string(fuzzBytes(must(xenc.GenerateEncryptedKey(fuzzOpts())).Element))
	i := strings.Index(valid, "</xenc:CipherValue>")
	f.Add([]byte(valid[:i-7] + valid[i:])) // truncated base64
	f.Add([]byte(valid[:i-3] + "!" + valid[i:]))
	f.Add([]byte(strings.Replace(valid, "<xenc11:MGF", "<xenc:OAEPparams>%%%</xenc:OAEPparams><xenc11:MGF", 1)))
	f.Add([]byte(strings.Replace(valid, "<xenc11:MGF", "<x:Unknown xmlns:x=\"urn:x\"/><xenc11:MGF", 1)))
	f.Add([]byte(`<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/>`))

	f.Fuzz(func(t *testing.T, doc []byte) {
		tree, err := xmlsec.Parse(doc)
		if err != nil {
			t.Skip()
		}
		el := fuzzFirst(tree.Root, "EncryptedKey")
		if el == nil {
			t.Skip()
		}
		xenc.DecryptEncryptedKey(el, recipientKey, nil, nil, nil)
		xenc.DecryptEncryptedKey(el, recipientKey, []string{xmlsec.KeyTransportRSAOAEP},
			[]string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
	})
}

func FuzzDecryptData(f *testing.F) {
	key := bytes.Repeat([]byte{7}, 16)
	opts := fuzzOpts()

	tree := must(xmlsec.Parse([]byte(`<S:Envelope xmlns:S="urn:s"><S:Body><p:Payload xmlns:p="urn:p">hi</p:Payload></S:Body></S:Envelope>`)))
	target := xmltree.DocumentElement(tree.Root).ChildElements()[0].ChildElements()[0]
	element := must(xenc.EncryptElement(tree.Root, target, key, opts))
	f.Add(element, []byte(nil))

	att := &xmlsec.Attachment{ID: "a@x", Body: []byte("compressed payload"),
		MIMEHeaders: map[string][]string{"Content-Type": {"application/gzip"}}}
	ct, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil {
		f.Fatal(err)
	}
	attachment := fuzzBytes(ed)
	f.Add(attachment, ct)
	f.Add(attachment, ct[:len(ct)-17]) // shorter than IV plus tag

	s := string(element)
	i := strings.Index(s, "</xenc:CipherValue>")
	f.Add([]byte(s[:i-5]+s[i:]), []byte(nil)) // truncated base64
	f.Add([]byte(strings.Replace(s, "<xenc:CipherValue>", "<xenc:CipherValue>AA", 1)), []byte(nil))
	f.Add([]byte(strings.Replace(s, xmlsec.EncAES128GCM, xmlsec.EncAES256GCM, 1)), []byte(nil))
	f.Add([]byte(`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod/>`+
		`<xenc:CipherData><xenc:CipherValue/><xenc:CipherReference URI="cid:"/></xenc:CipherData></xenc:EncryptedData>`), []byte{})

	keys := [][]byte{key, bytes.Repeat([]byte{7}, 32), nil}
	f.Fuzz(func(t *testing.T, doc, ciphertext []byte) {
		tree, err := xmlsec.Parse(doc)
		if err != nil {
			t.Skip()
		}
		el := fuzzFirst(tree.Root, "EncryptedData")
		if el == nil {
			t.Skip()
		}
		for _, k := range keys {
			xenc.DecryptData(el, k, nil)
			xenc.DecryptAttachment(el, ciphertext, k, nil)
		}
		xenc.DecryptData(el, key, []string{xmlsec.EncAES128GCM})
	})
}

// must panics on err. It is for fuzz setup only, which has no *testing.T.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
