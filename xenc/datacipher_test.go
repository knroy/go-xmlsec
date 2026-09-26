package xenc_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// covED is an xenc:EncryptedData with the given attributes and content.
func covED(attrs, content string) string {
	return `<xenc:EncryptedData xmlns:xenc="` + xenc.NSXEnc + `" ` + attrs + `>` + content + `</xenc:EncryptedData>`
}

func TestDecryptDataErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	em := covEM(xmlsec.EncAES128GCM)
	cv := func(b []byte) string {
		return `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(b) + `</xenc:CipherValue></xenc:CipherData>`
	}
	cases := []struct {
		name    string
		el      string
		key     []byte
		allowed []string
		want    error // nil: any error
	}{
		{"not EncryptedData", `<xenc:EncryptedKey xmlns:xenc="` + xenc.NSXEnc + `"/>`, key, nil, xmlsec.ErrMalformed},
		{"no EncryptionMethod", covED(``, cv(make([]byte, 40))), key, nil, xmlsec.ErrMalformed},
		{"EncryptionMethod not first", covED(``, cv(make([]byte, 40))+em), key, nil, xmlsec.ErrMalformed},
		{"unknown algorithm", covED(``, covEM("urn:x")+cv(make([]byte, 40))), key, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"CBC algorithm", covED(``, covEM("http://www.w3.org/2001/04/xmlenc#aes128-cbc")+cv(make([]byte, 40))), key, nil, xmlsec.ErrAlgorithmNotAllowed},
		{"allow-listed but unimplemented", covED(``, covEM("urn:x")+cv(make([]byte, 40))), key, []string{"urn:x"}, xmlsec.ErrUnsupportedAlgorithm},
		{"no CipherData", covED(``, em), key, nil, xmlsec.ErrMalformed},
		{"empty CipherData", covED(``, em+`<xenc:CipherData/>`), key, nil, xmlsec.ErrMalformed},
		{"CipherReference", covED(``, em+`<xenc:CipherData><xenc:CipherReference URI="cid:x"/></xenc:CipherData>`), key, nil, xmlsec.ErrMalformed},
		{"CipherValue not base64", covED(``, em+`<xenc:CipherData><xenc:CipherValue>!!</xenc:CipherValue></xenc:CipherData>`), key, nil, xmlsec.ErrMalformed},
		{"short ciphertext", covED(``, em+cv(make([]byte, 27))), key, nil, xmlsec.ErrMalformed},
		{"wrong session key length", covED(``, em+cv(make([]byte, 40))), make([]byte, 24), nil, nil},
		{"authentication failure", covED(``, em+cv(make([]byte, 40))), key, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt, err := xenc.DecryptData(covParse(t, c.el), c.key, c.allowed)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if pt != nil {
				t.Fatal("plaintext returned with an error")
			}
		})
	}
}

func TestEncryptElementErrors(t *testing.T) {
	const src = `<r><a>x</a><rel:b xmlns:rel="relative/uri"/></r>`
	tree, err := xmlsec.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	doc := tree.Root
	root := xmltree.DocumentElement(doc)
	other := covParse(t, `<o><a/></o>`)
	key := bytes.Repeat([]byte{1}, 16)

	cases := []struct {
		name   string
		target *xdm.Node
		key    []byte
		alg    string
		want   error // nil: any error
	}{
		{"target in another document", other.ChildElements()[0], key, xmlsec.EncAES128GCM, nil},
		{"detached target", xmltree.Element(nil, "", "", "d"), key, xmlsec.EncAES128GCM, nil},
		{"target is the document node", doc, key, xmlsec.EncAES128GCM, nil},
		{"target is text", root.ChildElements()[0].Children[0], key, xmlsec.EncAES128GCM, nil},
		{"unknown algorithm", root.ChildElements()[0], key, "urn:x", xmlsec.ErrUnsupportedAlgorithm},
		{"wrong session key length", root.ChildElements()[0], key[:8], xmlsec.EncAES128GCM, nil},
		{"target with no canonical form", root.ChildElements()[1], key, xmlsec.EncAES128GCM, c14n.ErrRelativeNamespaceURI},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := as4Opts(t)
			opts.DataAlgorithm = c.alg
			out, err := xenc.EncryptElement(doc, c.target, c.key, opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if out != nil {
				t.Fatal("output returned with an error")
			}
			if len(root.ChildElements()) != 2 || root.ChildElements()[0].Name.Local != "a" {
				t.Fatal("document modified")
			}
		})
	}
}

// Nil input from a failed lookup is an error, never a panic.
func TestNilInputs(t *testing.T) {
	key := make([]byte, 16)
	tree, err := xmlsec.Parse([]byte(`<r><a/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]error{}
	_, checks["DecryptEncryptedKey(nil)"] = xenc.DecryptEncryptedKey(nil, recipientKey, nil, nil, nil)
	_, checks["DecryptEncryptedKey(el, nil)"] = xenc.DecryptEncryptedKey(reparse(t, ek.Element), nil, nil, nil, nil)
	_, checks["DecryptData(nil)"] = xenc.DecryptData(nil, key, nil)
	_, checks["DecryptAttachment(nil)"] = xenc.DecryptAttachment(nil, nil, key, nil)
	_, checks["EncryptElement(nil, nil)"] = xenc.EncryptElement(nil, nil, key, as4Opts(t))
	_, checks["EncryptElement(doc, nil)"] = xenc.EncryptElement(tree.Root, nil, key, as4Opts(t))
	_, _, checks["EncryptAttachment(nil)"] = xenc.EncryptAttachment(nil, key, xmlsec.TransformAttachmentContentOnly, as4Opts(t))
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
