package security

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// An external reference reaches the caller's resolver only once the
// signature is authentic under an allowed algorithm and a trusted key: a
// message from anyone else cannot make the verifier fetch anything.
func TestResolverCalledOnlyForAuthenticSignatures(t *testing.T) {
	const uri = "http://example.invalid/data"
	signer := keyPair(t, rsaKey(t))
	tree, err := xmlsec.Parse([]byte(`<r/>`))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("payload")
	if _, err := dsig.Sign(tree.Root, signer, dsig.SignOptions{
		SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{URI: uri, DigestAlgorithm: xmlsec.DigestSHA256}},
		KeyInfo:    dsig.KeyInfoX509Data, Parent: xmltree.DocumentElement(tree.Root),
		ResolveURI: func(string) ([]byte, error) { return body, nil },
	}); err != nil {
		t.Fatal(err)
	}
	signed, err := c14n.Bytes(tree.Root, c14n.Options{Algorithm: c14n.Inclusive10})
	if err != nil {
		t.Fatal(err)
	}
	other := keyPair(t, rsaKey(t))
	errUnknown := errors.New("unknown sender")
	errGone := errors.New("gone")

	for _, c := range []struct {
		name    string
		doc     string
		opts    dsig.VerifyOptions
		fail    error
		want    error // nil: verifies
		fetched bool
	}{
		{"authentic", string(signed), dsig.VerifyOptions{Certificate: signer.Certificate}, nil, nil, true},
		{"untrusted key", string(signed), dsig.VerifyOptions{TrustKey: func(*x509.Certificate, crypto.PublicKey) error { return errUnknown }}, nil, xmlsec.ErrUntrusted, false},
		{"other pinned key", string(signed), dsig.VerifyOptions{Certificate: other.Certificate}, nil, xmlsec.ErrSignatureInvalid, false},
		{"signature algorithm not allowed", string(signed), dsig.VerifyOptions{AllowedSignatureAlgorithms: []string{xmlsec.SigECDSASHA256}}, nil, xmlsec.ErrAlgorithmNotAllowed, false},
		{"digest algorithm not allowed", string(signed), dsig.VerifyOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA512}}, nil, xmlsec.ErrAlgorithmNotAllowed, false},
		{"URI rewritten", strings.Replace(string(signed), uri, "http://169.254.169.254/latest", 1), dsig.VerifyOptions{Certificate: signer.Certificate}, nil, xmlsec.ErrSignatureInvalid, false},
		{"resolver fails", string(signed), dsig.VerifyOptions{Certificate: signer.Certificate}, errGone, errGone, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			c.opts.ResolveURI = func(u string) ([]byte, error) { calls = append(calls, u); return body, c.fail }
			doc, err := xmlsec.Parse([]byte(c.doc))
			if err != nil {
				t.Fatal(err)
			}
			sig, _, _, _ := elements(doc.Root)
			cov, err := dsig.Verify(doc.Root, sig, c.opts)
			switch {
			case c.want == nil && (err != nil || len(cov.ExternalURIs) != 1):
				t.Fatalf("got %v, %+v", err, cov)
			case !errors.Is(err, c.want):
				t.Fatalf("got %v, want %v", err, c.want)
			case c.fail != nil && !errors.Is(err, xmlsec.ErrDereference):
				t.Fatalf("resolver error not wrapped with ErrDereference: %v", err)
			case c.fetched != (len(calls) == 1):
				t.Fatalf("resolver calls %v", calls)
			}
		})
	}

	// Without a resolver the reference is refused, as it always was.
	doc, err := xmlsec.Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	sig, _, _, _ := elements(doc.Root)
	if _, err := dsig.Verify(doc.Root, sig, dsig.VerifyOptions{Certificate: signer.Certificate}); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Fatalf("no resolver: %v", err)
	}
}

// xenc.DecryptData calls the resolver only after the data algorithm passes
// the allow-list.
func TestCipherReferenceResolverAfterAllowList(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<xenc:EncryptedData xmlns:xenc="` + xmlsec.NSXEnc + `">` +
		`<xenc:EncryptionMethod Algorithm="` + xmlsec.EncAES128CBC + `"/>` +
		`<xenc:CipherData><xenc:CipherReference URI="http://example.invalid/ct"/></xenc:CipherData></xenc:EncryptedData>`))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = xenc.DecryptData(tree.Root.ChildElements()[0], make([]byte, 16), xenc.DecryptOptions{
		ResolveURI: func(string) ([]byte, error) { called = true; return nil, nil },
	})
	if !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) || called {
		t.Fatalf("got %v, resolver called %v", err, called)
	}
}

// An EncryptedKey's CipherReference reaches the resolver only once every
// algorithm the key needs has passed its allow-list, whichever function
// unwraps it.
func TestEncryptedKeyCipherReferenceResolverAfterAllowList(t *testing.T) {
	ref := `<xenc:CipherData><xenc:CipherReference URI="http://example.invalid/ek"/></xenc:CipherData>`
	ek := func(alg, method, keyInfo string) *xdm.Node {
		return legacyParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xmlsec.NSXEnc+`" xmlns:ds="`+xmlsec.NSDSig+`" xmlns:xenc11="`+xmlsec.NSXEnc11+`">`+
			`<xenc:EncryptionMethod Algorithm="`+alg+`">`+method+`</xenc:EncryptionMethod>`+keyInfo+ref+`</xenc:EncryptedKey>`)
	}
	concatKDF := func(digest string) string {
		return `<xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationConcatKDF + `"><xenc11:ConcatKDFParams AlgorithmID="00" PartyUInfo="" PartyVInfo="">` +
			`<ds:DigestMethod Algorithm="` + digest + `"/></xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>`
	}
	agreement := func(alg, digest string) string {
		return `<ds:KeyInfo><xenc:AgreementMethod Algorithm="` + alg + `">` + concatKDF(digest) +
			`<xenc:OriginatorKeyInfo><ds:KeyValue/></xenc:OriginatorKeyInfo></xenc:AgreementMethod></ds:KeyInfo>`
	}
	pbkdf2 := `<ds:KeyInfo><xenc11:DerivedKey><xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationPBKDF2 + `"/></xenc11:DerivedKey></ds:KeyInfo>`
	gcmED := legacyED(t, xmlsec.EncAES128GCM, make([]byte, 32))
	cbcED := legacyED(t, xmlsec.EncAES128CBC, make([]byte, 32))
	ec, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv := rsaKey(t)
	oaep := `<ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/><xenc11:MGF Algorithm="`
	for _, c := range []struct {
		name  string
		call  func(xenc.DecryptOptions) error
		allow func(*xenc.DecryptOptions)
	}{
		{"key wrap", func(o xenc.DecryptOptions) error {
			_, err := xenc.UnwrapEncryptedKey(ek(xmlsec.KeyWrapTripleDES, ``, ``), make([]byte, 24), o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedKeyWrapAlgorithms = []string{xmlsec.KeyWrapTripleDES} }},
		{"RSA-OAEP MGF", func(o xenc.DecryptOptions) error {
			_, err := xenc.DecryptEncryptedKey(ek(xmlsec.KeyTransportRSAOAEP, oaep+xmlsec.MGF1SHA224+`"/>`, ``), rsaPriv, o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedMGFAlgorithms = []string{xmlsec.MGF1SHA224} }},
		{"RSA v1.5", func(o xenc.DecryptOptions) error {
			_, err := xenc.DecryptEncryptedKeyPKCS1v15(ek(xmlsec.KeyTransportRSA15, ``, ``), gcmED, rsaPriv, o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedKeyTransportAlgorithms = []string{xmlsec.KeyTransportRSA15} }},
		{"RSA v1.5 data algorithm", func(o xenc.DecryptOptions) error {
			o.AllowedKeyTransportAlgorithms = []string{xmlsec.KeyTransportRSA15}
			_, err := xenc.DecryptEncryptedKeyPKCS1v15(ek(xmlsec.KeyTransportRSA15, ``, ``), cbcED, rsaPriv, o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedDataAlgorithms = []string{xmlsec.EncAES128CBC} }},
		{"key agreement", func(o xenc.DecryptOptions) error {
			_, err := xenc.DecryptAgreedKey(ek(xmlsec.KeyWrapAES128, ``, agreement("urn:x", xmlsec.DigestSHA256)), ec, o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedKeyAgreementAlgorithms = []string{"urn:x"} }},
		{"ConcatKDF digest", func(o xenc.DecryptOptions) error {
			_, err := xenc.DecryptAgreedKey(ek(xmlsec.KeyWrapAES128, ``, agreement(xmlsec.KeyAgreementECDHES, xmlsec.DigestSHA1)), ec, o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedDigestAlgorithms = []string{xmlsec.DigestSHA1} }},
		{"PBKDF2", func(o xenc.DecryptOptions) error {
			_, err := xenc.UnwrapEncryptedKeyPassword(ek(xmlsec.KeyWrapAES128, ``, pbkdf2), []byte("pw"), o)
			return err
		}, func(o *xenc.DecryptOptions) { o.AllowedKeyDerivationAlgorithms = []string{xmlsec.KeyDerivationPBKDF2} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			called := false
			opts := xenc.DecryptOptions{ResolveURI: func(string) ([]byte, error) { called = true; return nil, errors.New("offline") }}
			if err := c.call(opts); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) || called {
				t.Fatalf("got %v, resolver called %v", err, called)
			}
			// Named, the same message passes that allow-list.
			c.allow(&opts)
			if err := c.call(opts); errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("still refused: %v", err)
			}
		})
	}
}
