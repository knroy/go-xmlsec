package xenc_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

// Section 2.1.4: arbitrary octets, inline or by CipherReference, with the
// Type, MimeType and Encoding that describe them.
func TestEncryptOctets(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	png := []byte("\x89PNG\r\n\x1a\n\x00binary")
	opts := xenc.EncryptOptions{
		DataAlgorithm: xmlsec.EncAES128GCM,
		Type:          "http://www.iana.org/assignments/media-types/image/png",
		MimeType:      "image/png",
		Encoding:      xmlsec.TransformBase64,
		DataID:        "img",
	}

	ct, ed, err := xenc.EncryptOctets(png, key, opts)
	if err != nil || ct != nil {
		t.Fatalf("inline: %x, %v", ct, err)
	}
	for attr, want := range map[string]string{"Id": "img", "Type": opts.Type, "MimeType": "image/png", "Encoding": xmlsec.TransformBase64} {
		if got := ed.AttrValue(attr); got != want {
			t.Errorf("%s = %q, want %q", attr, got, want)
		}
	}
	if pt, err := xenc.DecryptData(reparse(t, ed), key, xenc.DecryptOptions{}); err != nil || !bytes.Equal(pt, png) {
		t.Fatalf("inline: %q, %v", pt, err)
	}

	// No Type at all: it is optional.
	if _, ed, err := xenc.EncryptOctets(png, key, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM}); err != nil || ed.Attr("", "Type") != nil {
		t.Fatalf("no Type: %v", err)
	}

	opts.CipherReferenceURI = "images/1.bin"
	ct, ed, err = xenc.EncryptOctets(png, key, opts)
	if err != nil || ct == nil {
		t.Fatalf("referenced: %v", err)
	}
	cr := firstNamed(ed, "CipherReference")
	if cr == nil || cr.AttrValue("URI") != "images/1.bin" || len(cr.ChildElements()) != 0 {
		t.Fatal("no CipherReference to the URI")
	}
	pt, err := xenc.DecryptData(reparse(t, ed), key, xenc.DecryptOptions{
		BaseURI: "https://example.com/msg",
		ResolveURI: func(u string) ([]byte, error) {
			if u != "https://example.com/images/1.bin" {
				t.Fatalf("resolved %q", u)
			}
			return ct, nil
		},
	})
	if err != nil || !bytes.Equal(pt, png) {
		t.Fatalf("referenced: %q, %v", pt, err)
	}

	for name, o := range map[string]xenc.EncryptOptions{
		"same-document URI": {DataAlgorithm: xmlsec.EncAES128GCM, CipherReferenceURI: "#ct"},
		"unparsable URI":    {DataAlgorithm: xmlsec.EncAES128GCM, CipherReferenceURI: "http://[::1"},
		"bad DataID":        {DataAlgorithm: xmlsec.EncAES128GCM, DataID: "1x"},
		"CBC":               {DataAlgorithm: xmlsec.EncAES128CBC},
	} {
		t.Run(name, func(t *testing.T) {
			if ct, ed, err := xenc.EncryptOctets(png, key, o); err == nil || ct != nil || ed != nil {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// CBC is decryption-only.
	if _, _, err := xenc.EncryptOctets(png, key, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128CBC}); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
}
