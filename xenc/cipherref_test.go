package xenc_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
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
		{"Attachment-Complete-Signature-Transform", xmlsec.TransformAttachmentCompleteSignature, xmlsec.EncAES128GCM, key, xmlsec.ErrUnsupportedAlgorithm},
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
			// SwA profile sections 5.5.2 step 4 and 5.4.1 rule 2.
			const def = "text/plain; charset=us-ascii"
			if got := ed.AttrValue("MimeType"); got != def {
				t.Fatalf("MimeType %q without a Content-Type", got)
			}
			pt, err := xenc.DecryptAttachment(reparse(t, ed), ct, key, xenc.DecryptOptions{})
			if err != nil || !bytes.Equal(pt.Body, att.Body) || pt.MIMEHeaders["Content-Type"][0] != def {
				t.Fatalf("round trip %q, %v", pt, err)
			}
			// Attachment-Complete carries the headers inside: no default.
			_, ed, err = xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a@x"}, key, xmlsec.TransformAttachmentComplete, opts)
			if err != nil || ed.Attr("", "MimeType") != nil {
				t.Fatalf("Attachment-Complete MimeType: %v", err)
			}
		})
	}
}

// attTransform is the xenc:Transforms the SwA profile requires on an
// attachment's CipherReference (section 5.5.1).
const attTransform = `<xenc:Transforms><ds:Transform xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + xmlsec.TransformAttachmentCiphertext + `"/></xenc:Transforms>`

func TestDecryptAttachmentErrors(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	em := covEM(xmlsec.EncAES128GCM)
	typ := `Type="` + xmlsec.TransformAttachmentContentOnly + `"`
	ref := func(uri string) string {
		return `<xenc:CipherData><xenc:CipherReference URI="` + uri + `">` + attTransform + `</xenc:CipherReference></xenc:CipherData>`
	}
	cases := []struct {
		name string
		el   string
		ct   []byte
		key  []byte
		want error // nil: any error
	}{
		{"not EncryptedData", `<xenc:EncryptedKey xmlns:xenc="` + xmlsec.NSXEnc + `"/>`, make([]byte, 40), key, xmlsec.ErrMalformed},
		{"unknown algorithm", covED(typ, covEM("urn:x")+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrAlgorithmNotAllowed},
		{"no Type", covED(``, em+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrUnsupportedAlgorithm},
		{"Element Type", covED(`Type="`+xenc.TypeElement+`"`, em+ref("cid:a")), make([]byte, 40), key, xmlsec.ErrUnsupportedAlgorithm},
		{"undecodable cid", covED(typ, em+ref("cid:%zz")), make([]byte, 40), key, xmlsec.ErrMalformed},
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
			pt, err := xenc.DecryptAttachment(covParse(t, c.el), c.ct, c.key, xenc.DecryptOptions{})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if pt != nil {
				t.Fatal("plaintext returned with an error")
			}
		})
	}
}

// Attachment-Complete encrypts the listed headers with the body, as a MIME
// part WSS4J reads: each "Name: value" unfolded, in the profile's order,
// then an empty line. Unlisted headers stay outside.
func TestEncryptAttachmentComplete(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	att := &xmlsec.Attachment{ID: "a@x", Body: []byte("<doc/>\r\n"), MIMEHeaders: map[string][]string{
		"content-type":              {"text/xml; charset=UTF-8"},
		"Content-Description":       {"an\r\n attachment"},
		"Content-Id":                {"<a@x>"},
		"Content-Transfer-Encoding": {"binary"},
	}}
	ct, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentComplete, as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	ed = reparse(t, ed)
	if ed.AttrValue("Type") != xmlsec.TransformAttachmentComplete || ed.AttrValue("MimeType") != "text/xml; charset=UTF-8" {
		t.Fatalf("attributes %q %q", ed.AttrValue("Type"), ed.AttrValue("MimeType"))
	}
	want := "Content-Description: an attachment\r\nContent-ID: <a@x>\r\nContent-Type: text/xml; charset=UTF-8\r\n\r\n<doc/>\r\n"
	if got := openGCM(t, key, ct); got != want {
		t.Fatalf("plaintext %q, want %q", got, want)
	}

	got, err := xenc.DecryptAttachment(ed, ct, key, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "a@x" || !bytes.Equal(got.Body, att.Body) || len(got.MIMEHeaders) != 3 ||
		got.MIMEHeaders["Content-ID"][0] != "<a@x>" || got.MIMEHeaders["Content-Type"][0] != "text/xml; charset=UTF-8" {
		t.Fatalf("decrypted %+v", got)
	}

	att.MIMEHeaders["CONTENT-TYPE"] = []string{"text/plain"}
	if _, _, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentComplete, as4Opts(t)); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("duplicate header: %v", err)
	}
}

// RFC 2392 and section 3.3.1: the cid: URI percent-encodes the Content-ID
// so that decoding it names the same part. "@" and the unreserved
// characters stay; "+", which WSS4J would decode as a space, does not.
func TestCipherReferenceCIDEncoding(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	for id, uri := range map[string]string{
		"a@x":                 "cid:a@x",
		"part-1.x_y~z@host":   "cid:part-1.x_y~z@host",
		"50%off @x":           "cid:50%25off%20@x",
		"a+b/c?d#e@x":         "cid:a%2Bb%2Fc%3Fd%23e@x",
		"café@x":              "cid:caf%C3%A9@x",
		"<angle>&\"quote\"@x": "cid:%3Cangle%3E%26%22quote%22@x",
	} {
		att := &xmlsec.Attachment{ID: id, Body: []byte("b")}
		ct, ed, err := xenc.EncryptAttachment(att, key, xmlsec.TransformAttachmentContentOnly, as4Opts(t))
		if err != nil {
			t.Fatal(err)
		}
		ed = reparse(t, ed)
		cr := firstNamed(ed, "CipherReference")
		if cr.AttrValue("URI") != uri {
			t.Errorf("%q: URI %q, want %q", id, cr.AttrValue("URI"), uri)
		}
		got, err := xenc.DecryptAttachment(ed, ct, key, xenc.DecryptOptions{})
		if err != nil || got.ID != id {
			t.Errorf("%q: decrypted ID %q, %v", id, got.ID, err)
		}
		set, _ := xmlsec.NewAttachmentSet(att)
		if found, err := set.Lookup(uri); err != nil || found != att {
			t.Errorf("%q: Lookup %v", id, err)
		}
	}
}

// Section 3.3.1 transforms on an attachment CipherReference: none, or the
// SwA Attachment-Ciphertext-Transform alone, which the profile requires.
func TestDecryptAttachmentTransforms(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	ct := sealGCM(key, "body")
	el := func(transforms string) *xdm.Node {
		return covParse(t, covED(`Type="`+xmlsec.TransformAttachmentContentOnly+`"`, covEM(xmlsec.EncAES128GCM)+
			`<xenc:CipherData><xenc:CipherReference URI="cid:a">`+transforms+`</xenc:CipherReference></xenc:CipherData>`))
	}
	tr := func(algs ...string) string {
		s := `<xenc:Transforms>`
		for _, a := range algs {
			s += `<ds:Transform xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + a + `"/>`
		}
		return s + `</xenc:Transforms>`
	}
	if got, err := xenc.DecryptAttachment(el(tr(xmlsec.TransformAttachmentCiphertext)), ct, key, xenc.DecryptOptions{}); err != nil || string(got.Body) != "body" {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		transforms string
		want       error
	}{
		"none":           {``, xmlsec.ErrUnsupportedAlgorithm},
		"empty":          {tr(), xmlsec.ErrUnsupportedAlgorithm},
		"XSLT":           {tr(xmlsec.TransformXSLT), xmlsec.ErrTransformRefused},
		"XPath":          {`<xenc:Transforms><ds:Transform xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + xmlsec.TransformXPath + `"><ds:XPath>1</ds:XPath></ds:Transform></xenc:Transforms>`, xmlsec.ErrTransformRefused},
		"XPath after":    {tr(xmlsec.TransformAttachmentCiphertext, xmlsec.TransformXPathFilter2), xmlsec.ErrTransformRefused},
		"base64":         {tr(xmlsec.TransformBase64), xmlsec.ErrUnsupportedAlgorithm},
		"twice":          {tr(xmlsec.TransformAttachmentCiphertext, xmlsec.TransformAttachmentCiphertext), xmlsec.ErrUnsupportedAlgorithm},
		"signature form": {tr(xmlsec.TransformAttachmentContentSignature), xmlsec.ErrUnsupportedAlgorithm},
		"ds:Transforms":  {`<ds:Transforms xmlns:ds="` + xmlsec.NSDSig + `"/>`, xmlsec.ErrMalformed},
		"two Transforms": {tr() + tr(), xmlsec.ErrMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := xenc.DecryptAttachment(el(c.transforms), ct, key, xenc.DecryptOptions{})
			if !errors.Is(err, c.want) || got != nil {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// openGCM opens IV || ciphertext || tag without the library.
func openGCM(t *testing.T, key, ct []byte) string {
	t.Helper()
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	pt, err := a.Open(nil, ct[:12], ct[12:], nil)
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

// sealGCM builds IV || ciphertext || tag without the library, so a test can
// encrypt a plaintext EncryptAttachment would never produce.
func sealGCM(key []byte, pt string) []byte {
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	iv := make([]byte, 12)
	return a.Seal(iv, iv, []byte(pt), nil)
}

func TestDecryptAttachmentComplete(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	el := covParse(t, covED(`Type="`+xmlsec.TransformAttachmentComplete+`"`,
		covEM(xmlsec.EncAES128GCM)+`<xenc:CipherData><xenc:CipherReference URI="cid:a%40x">`+attTransform+`</xenc:CipherReference></xenc:CipherData>`))

	got, err := xenc.DecryptAttachment(el, sealGCM(key, "\r\nbody"), key, xenc.DecryptOptions{})
	if err != nil || got.ID != "a@x" || string(got.Body) != "body" || len(got.MIMEHeaders) != 0 {
		t.Fatalf("no headers: %+v, %v", got, err)
	}
	got, err = xenc.DecryptAttachment(el, sealGCM(key, "Content-Type:text/plain\r\nContent-Description: a\r\n b\r\n\r\n\r\nbody"), key, xenc.DecryptOptions{})
	if err != nil || string(got.Body) != "\r\nbody" || got.MIMEHeaders["Content-Description"][0] != "a b" {
		t.Fatalf("folded header: %+v, %v", got, err)
	}

}

// Sections 6.1.1 and 6.7: once Attachment-Complete ciphertext decrypts,
// nothing about the plaintext's format is told apart from a wrong key or,
// for CBC, bad padding. Every failure is the one generic error.
func TestDecryptAttachmentCompleteNoOracle(t *testing.T) {
	alg := xmlsec.EncAES128CBC
	key := cbcKey(alg)
	el := covParse(t, covED(`Type="`+xmlsec.TransformAttachmentComplete+`"`,
		covEM(alg)+`<xenc:CipherData><xenc:CipherReference URI="cid:a">`+attTransform+`</xenc:CipherReference></xenc:CipherData>`))
	opts := xenc.DecryptOptions{AllowedDataAlgorithms: []string{alg}}
	good := "Content-Type: text/plain\r\n\r\nbody"
	if got, err := xenc.DecryptAttachment(el, cbcSeal(t, alg, key, []byte(good), -1), key, opts); err != nil || string(got.Body) != "body" {
		t.Fatalf("%+v, %v", got, err)
	}
	cases := map[string]struct {
		ct, key []byte
	}{
		"bad padding":     {cbcSeal(t, alg, key, []byte(good), 0), key},
		"wrong key":       {cbcSeal(t, alg, key, []byte(good), -1), make([]byte, len(key))},
		"bad header":      {cbcSeal(t, alg, key, []byte("Content-Type text/plain\r\n\r\nbody"), -1), key},
		"no empty line":   {cbcSeal(t, alg, key, []byte("Content-Type: text/plain\r\nbody"), -1), key},
		"unlisted header": {cbcSeal(t, alg, key, []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\n\r\nbody"), -1), key},
		"header twice":    {cbcSeal(t, alg, key, []byte("Content-Type: text/plain\r\ncontent-type: text/xml\r\n\r\nbody"), -1), key},
	}
	var first error
	for name, c := range cases {
		got, err := xenc.DecryptAttachment(el, c.ct, c.key, opts)
		if got != nil || !errors.Is(err, xmlsec.ErrDecryptionFailed) {
			t.Fatalf("%s: %+v, %v", name, got, err)
		}
		if first == nil {
			first = err
		}
		if err != first || errors.Is(err, xmlsec.ErrMalformed) {
			t.Fatalf("%s: %v differs from %v", name, err, first)
		}
	}
}
