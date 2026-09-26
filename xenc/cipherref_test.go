package xenc_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

func TestEncryptAttachmentErrors(t *testing.T) {
	att := &xmlsec.Attachment{ID: "a@x", Body: []byte("body")}
	key := bytes.Repeat([]byte{1}, 16)
	cases := []struct {
		name      string
		transform string
		alg       string
		key       []byte
		want      error // nil: any error
	}{
		{"Attachment-Complete", xmlsec.TransformAttachmentComplete, xmlsec.EncAES128GCM, key, xmlsec.ErrUnsupportedAlgorithm},
		{"no transform", "", xmlsec.EncAES128GCM, key, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown data algorithm", xmlsec.TransformAttachmentContentOnly, "urn:x", key, xmlsec.ErrUnsupportedAlgorithm},
		{"wrong session key length", xmlsec.TransformAttachmentContentOnly, xmlsec.EncAES256GCM, key, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := as4Opts(t)
			opts.DataAlgorithm = c.alg
			ct, ed, err := xenc.EncryptAttachment(att, c.key, c.transform, opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if ct != nil || ed != nil {
				t.Fatal("output returned with an error")
			}
		})
	}
}

func TestEncryptAttachmentMimeType(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	opts := as4Opts(t)
	opts.DataAlgorithm = xmlsec.EncAES256GCM
	for name, headers := range map[string]map[string][]string{
		"no headers":         nil,
		"empty Content-Type": {"Content-Type": {}},
		"other headers only": {"Content-ID": {"<a@x>"}},
	} {
		t.Run(name, func(t *testing.T) {
			att := &xmlsec.Attachment{ID: "a@x", Body: []byte("body"), MIMEHeaders: headers}
			ct, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, opts)
			if err != nil {
				t.Fatal(err)
			}
			if ed.Attr("", "MimeType") != nil {
				t.Fatal("MimeType emitted without a Content-Type")
			}
			pt, err := xenc.DecryptAttachment(reparse(t, ed), ct, key, nil)
			if err != nil || !bytes.Equal(pt, att.Body) {
				t.Fatalf("round trip %q, %v", pt, err)
			}
		})
	}
}

func TestDecryptAttachmentErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	em := covEM(xmlsec.EncAES128GCM)
	typ := `Type="` + xmlsec.TransformAttachmentContentOnly + `"`
	ref := func(uri string) string {
		return `<xenc:CipherData><xenc:CipherReference URI="` + uri + `"/></xenc:CipherData>`
	}
	cases := []struct {
		name string
		el   string
		ct   []byte
		key  []byte
		want error // nil: any error
	}{
		{"not EncryptedData", `<xenc:EncryptedKey xmlns:xenc="` + xenc.NSXEnc + `"/>`, make([]byte, 40), key, xmlsec.ErrMalformed},
		{"unknown algorithm", covED(typ, covEM("urn:x")+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrAlgorithmNotAllowed},
		{"no Type", covED(``, em+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrUnsupportedAlgorithm},
		{"Element Type", covED(`Type="`+xenc.TypeElement+`"`, em+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrUnsupportedAlgorithm},
		{"Attachment-Complete Type", covED(`Type="`+xmlsec.TransformAttachmentComplete+`"`, em+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrUnsupportedAlgorithm},
		{"no CipherData", covED(typ, em), make([]byte, 40), key, xmlsec.ErrMalformed},
		{"CipherValue instead of CipherReference", covED(typ, em+`<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>`), make([]byte, 40), key, xmlsec.ErrMalformed},
		{"CipherReference without URI", covED(typ, em+`<xenc:CipherData><xenc:CipherReference/></xenc:CipherData>`), make([]byte, 40), key, xmlsec.ErrMalformed},
		{"non-cid CipherReference", covED(typ, em+ref("http://example.com/a")), make([]byte, 40), key, xmlsec.ErrMalformed},
		{"two CipherReferences", covED(typ, em+`<xenc:CipherData><xenc:CipherReference URI="cid:a"/><xenc:CipherReference URI="cid:b"/></xenc:CipherData>`), make([]byte, 40), key, xmlsec.ErrMalformed},
		{"short ciphertext", covED(typ, em+ref("cid:a")), make([]byte, 27), key, xmlsec.ErrMalformed},
		{"wrong session key length", covED(typ, em+ref("cid:a")), make([]byte, 40), key[:10], nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pt, err := xenc.DecryptAttachment(covParse(t, c.el), c.ct, c.key, nil)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if pt != nil {
				t.Fatal("plaintext returned with an error")
			}
		})
	}
}
