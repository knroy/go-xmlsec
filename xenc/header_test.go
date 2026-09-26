package xenc_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// WS-Security 1.1.1 section 9.4.3: the block becomes a
// wsse11:EncryptedHeader holding the EncryptedData, carrying the
// referencing Security header's mustUnderstand and actor or role.
func TestEncryptHeader(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	for _, c := range []struct {
		name, ns, secAttrs, want string
	}{
		{"SOAP 1.1", soap11, `S:mustUnderstand="1" S:actor="urn:next"`, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" S:actor="urn:next" S:mustUnderstand="1">`},
		{"SOAP 1.2", soap12, `S:mustUnderstand="true" S:role="urn:r" S:relay="true" other="x"`, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `" S:mustUnderstand="true" S:relay="true" S:role="urn:r">`},
		{"prefix declared on Security", soap12, `xmlns:e="` + soap12 + `" e:mustUnderstand="true"`, `<wsse11:EncryptedHeader xmlns:e="` + soap12 + `" xmlns:wsse11="` + xmlsec.NSWSSE11 + `" e:mustUnderstand="true">`},
		{"no attributes", soap12, ``, `<wsse11:EncryptedHeader xmlns:wsse11="` + xmlsec.NSWSSE11 + `">`},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := covParse(t, `<S:Envelope xmlns:S="`+c.ns+`"><S:Header>`+
				`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" `+c.secAttrs+`></wsse:Security>`+
				`<m:Block xmlns:m="urn:m" S:mustUnderstand="1" secret="s">v</m:Block></S:Header><S:Body/></S:Envelope>`)
			hdr := doc.ChildElements()[0]
			sec, block := hdr.ChildElements()[0], hdr.ChildElements()[1]
			opts := as4Opts(t)
			opts.DataID = "ED-h"
			out, err := xenc.EncryptHeader(doc, block, sec, key, opts)
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			if !strings.Contains(s, c.want+`<xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`" Id="ED-h" Type="`+xenc.TypeElement+`">`) ||
				strings.Contains(s, "secret") || strings.Contains(s, "Block") {
				t.Fatalf("encrypted:\n%s", s)
			}
			if pt := decryptIn(t, out, key); !strings.HasPrefix(pt, `<m:Block xmlns:S="`+c.ns+`" xmlns:m="urn:m" secret="s" S:mustUnderstand="1">`) {
				t.Fatalf("plaintext %s", pt)
			}
			if len(hdr.ChildElements()) != 2 || hdr.ChildElements()[1] != block {
				t.Fatal("doc modified")
			}
		})
	}
}

func TestEncryptHeaderErrors(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	doc := covParse(t, `<S:Envelope xmlns:S="`+soap12+`" xmlns:x="urn:x"><S:Header>`+
		`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`"/>`+
		`<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`" xmlns:x="`+soap12+`" x:mustUnderstand="true"/>`+
		`<b>v</b></S:Header><S:Body><c/></S:Body></S:Envelope>`)
	hdr := doc.ChildElements()[0]
	sec, clash, block := hdr.ChildElements()[0], hdr.ChildElements()[1], hdr.ChildElements()[2]
	other := covParse(t, `<wsse:Security xmlns:wsse="`+xmlsec.NSWSSE+`"/>`)
	for name, c := range map[string]struct {
		block, sec *xdm.Node
		dataAlg    string
	}{
		"not a header block":       {doc.ChildElements()[1].ChildElements()[0], sec, ""},
		"not in doc":               {other, sec, ""},
		"no Security":              {block, nil, ""},
		"Security is not Security": {block, doc.ChildElements()[1], ""},
		"Security is the block":    {sec, sec, ""},
		"Security in another doc":  {block, other, ""},
		"prefix bound elsewhere":   {block, clash, ""},
		"unknown data algorithm":   {block, sec, "urn:x"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := as4Opts(t)
			if c.dataAlg != "" {
				opts.DataAlgorithm = c.dataAlg
			}
			if out, err := xenc.EncryptHeader(doc, c.block, c.sec, key, opts); err == nil || out != nil {
				t.Fatalf("got %v", err)
			}
		})
	}
}
