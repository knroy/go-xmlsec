package dsig_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func hmacOpts(alg string) dsig.SignOptions {
	return dsig.SignOptions{
		SignatureAlgorithm:        alg,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		HMACKey:                   hmacSecret,
		References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformEnvelopedSignature}, excC14N[0]}}},
	}
}

// XML-DSig 6.3: Sign produces HMAC-SHA2 with a shared secret and no
// KeyProvider, full length or truncated, and Verify accepts it with the same
// secret only.
func TestSignHMAC(t *testing.T) {
	long := []byte(strings.Repeat("k", 64))
	cases := []struct {
		alg     string
		key     []byte
		bits    int
		wantLen int
	}{
		{xmlsec.SigHMACSHA256, hmacSecret, 0, 32},
		{xmlsec.SigHMACSHA256, hmacSecret, 128, 16},
		{xmlsec.SigHMACSHA384, long, 0, 48},
		{xmlsec.SigHMACSHA512, long, 264, 33},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			opts := hmacOpts(c.alg)
			opts.HMACKey, opts.HMACOutputLength = c.key, c.bits
			signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), xmlsec.KeyProvider{}, opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(string(signed), "<ds:HMACOutputLength>"); got != (c.bits > 0) || strings.Contains(string(signed), "KeyInfo") {
				t.Fatalf("HMACOutputLength emitted %v, or a KeyInfo:\n%s", got, signed)
			}
			doc := parse(t, signed)
			vopts := dsig.VerifyOptions{HMACKey: c.key, AllowedSignatureAlgorithms: []string{c.alg}}
			cov, err := dsig.Verify(doc, findSignature(doc), vopts)
			if err != nil || !cov.WholeDocumentSigned {
				t.Fatal(err)
			}
			if v, _ := xmltree.Base64(findSignature(doc).ChildElements()[1]); len(v) != c.wantLen {
				t.Fatalf("SignatureValue of %d octets", len(v))
			}
			vopts.HMACKey = []byte(strings.Repeat("x", 64))
			if _, err := dsig.Verify(doc, findSignature(doc), vopts); !errors.Is(err, xmlsec.ErrSignatureInvalid) {
				t.Fatalf("another secret: %v", err)
			}
		})
	}
}

func TestSignHMACRefusals(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*dsig.SignOptions)
		want error
	}{
		{"hmac-sha1", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigHMACSHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"not an HMAC", func(o *dsig.SignOptions) { o.SignatureAlgorithm = xmlsec.SigRSASHA256 }, xmlsec.ErrUnsupportedAlgorithm},
		{"key shorter than the hash", func(o *dsig.SignOptions) { o.HMACKey = hmacSecret[:31] }, xmlsec.ErrUnsupportedKeyInfo},
		{"KeyInfo", func(o *dsig.SignOptions) { o.KeyInfo = dsig.KeyInfoX509Data }, xmlsec.ErrUnsupportedKeyInfo},
		{"output length not a multiple of 8", func(o *dsig.SignOptions) { o.HMACOutputLength = 130 }, xmlsec.ErrMalformed},
		{"output length below half", func(o *dsig.SignOptions) { o.HMACOutputLength = 120 }, xmlsec.ErrMalformed},
		{"output length above the hash", func(o *dsig.SignOptions) { o.HMACOutputLength = 264 }, xmlsec.ErrMalformed},
		{"negative output length", func(o *dsig.SignOptions) { o.HMACOutputLength = -8 }, xmlsec.ErrMalformed},
		{"output length without a key", func(o *dsig.SignOptions) {
			o.HMACKey, o.SignatureAlgorithm, o.HMACOutputLength = nil, xmlsec.SigRSASHA256, 128
		}, xmlsec.ErrMalformed},
		{"HMAC-SHA2 without a key", func(o *dsig.SignOptions) { o.HMACKey = nil }, xmlsec.ErrUnsupportedAlgorithm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := hmacOpts(xmlsec.SigHMACSHA256)
			c.mod(&opts)
			if _, err := dsig.SignEnveloped(parse(t, []byte(metadata)), xmlsec.KeyProvider{}, opts); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}
