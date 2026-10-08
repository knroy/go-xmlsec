package xenc_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

func covCert(t *testing.T, pub, priv any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "c"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func covParse(t *testing.T, s string) *xdm.Node {
	t.Helper()
	tree, err := xmlsec.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return xmltree.DocumentElement(tree.Root)
}

func TestGenerateEncryptedKeyErrors(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCert := covCert(t, &ec.PublicKey, ec)
	// A 1024-bit modulus cannot carry a SHA-512 OAEP block.
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallCert := covCert(t, &small.PublicKey, small)

	cases := []struct {
		name string
		mod  func(*xenc.EncryptOptions)
		want error // nil: any error
	}{
		{"unknown data algorithm", func(o *xenc.EncryptOptions) { o.DataAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"CBC data algorithm", func(o *xenc.EncryptOptions) {
			o.DataAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"legacy key transport", func(o *xenc.EncryptOptions) {
			o.KeyTransportAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		}, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown MGF", func(o *xenc.EncryptOptions) { o.MGFAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"missing MGF", func(o *xenc.EncryptOptions) { o.MGFAlgorithm = "" }, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown digest", func(o *xenc.EncryptOptions) { o.DigestAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"nil recipient", func(o *xenc.EncryptOptions) { o.Recipient = nil }, nil},
		{"ECDSA recipient", func(o *xenc.EncryptOptions) { o.Recipient = ecCert }, xmlsec.ErrUnsupportedAlgorithm},
		{"session key too short", func(o *xenc.EncryptOptions) { o.SessionKey = make([]byte, 15) }, nil},
		{"session key for another algorithm", func(o *xenc.EncryptOptions) { o.SessionKey = make([]byte, 32) }, nil},
		{"recipient key too small", func(o *xenc.EncryptOptions) {
			o.Recipient, o.DigestAlgorithm = smallCert, xmlsec.DigestSHA512
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := as4Opts(t)
			c.mod(&opts)
			ek, err := xenc.GenerateEncryptedKey(opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if ek != nil {
				t.Fatal("key returned with an error")
			}
		})
	}
}

func TestGenerateEncryptedKeyFixedSessionKey(t *testing.T) {
	opts := as4Opts(t)
	opts.SessionKey = bytes.Repeat([]byte{9}, 16)
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	key, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, xenc.DecryptOptions{})
	if err != nil || !bytes.Equal(key, opts.SessionKey) {
		t.Fatalf("unwrapped %x, %v", key, err)
	}
}

// covEK is an xenc:EncryptedKey with the given EncryptionMethod content and
// trailing content.
func covEK(alg, method, rest string) string {
	return `<xenc:EncryptedKey xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:xenc11="` + xmlsec.NSXEnc11 + `" xmlns:ds="` + xmlsec.NSDSig + `">` +
		`<xenc:EncryptionMethod Algorithm="` + alg + `">` + method + `</xenc:EncryptionMethod>` + rest + `</xenc:EncryptedKey>`
}

func covMethod(mgf, digest string) string {
	return `<ds:DigestMethod Algorithm="` + digest + `"/><xenc11:MGF Algorithm="` + mgf + `"/>`
}

func TestDecryptEncryptedKeyErrors(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	cd := `<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(make([]byte, 256)) + `</xenc:CipherValue></xenc:CipherData>`
	kt := xmlsec.KeyTransportRSAOAEP
	good := covMethod(xmlsec.MGF1SHA256, xmlsec.DigestSHA256)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	type lists struct{ kt, mgf, digest []string }
	cases := []struct {
		name  string
		el    *xdm.Node
		dec   *rsa.PrivateKey
		allow lists
		want  error // nil: any error
	}{
		{"not an EncryptedKey", covParse(t, `<xenc:EncryptedData xmlns:xenc="`+xmlsec.NSXEnc+`"/>`), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"no EncryptionMethod", covParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xmlsec.NSXEnc+`">`+cd+`</xenc:EncryptedKey>`), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"unexpected method child", covParse(t, covEK(kt, good+`<xenc:KeySize>128</xenc:KeySize>`, cd)), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"OAEPparams not base64", covParse(t, covEK(kt, `<xenc:OAEPparams>!!</xenc:OAEPparams>`+good, cd)), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"implicit SHA-1 digest", covParse(t, covEK(kt, `<xenc11:MGF Algorithm="`+xmlsec.MGF1SHA256+`"/>`, cd)), recipientKey, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"legacy key transport", covParse(t, covEK("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", good, cd)), recipientKey, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown MGF", covParse(t, covEK(kt, covMethod("urn:x", xmlsec.DigestSHA256), cd)), recipientKey, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"unknown digest", covParse(t, covEK(kt, covMethod(xmlsec.MGF1SHA256, "urn:x"), cd)), recipientKey, lists{}, xmlsec.ErrAlgorithmNotAllowed},
		{"digest outside allow-list", reparse(t, ek.Element), recipientKey, lists{digest: []string{xmlsec.DigestSHA512}}, xmlsec.ErrAlgorithmNotAllowed},
		{"key transport outside allow-list", reparse(t, ek.Element), recipientKey, lists{kt: []string{"urn:x"}}, xmlsec.ErrAlgorithmNotAllowed},
		// A caller allow-list cannot enable what this package does not implement.
		{"allow-listed but unimplemented", covParse(t, covEK("urn:x", good, cd)), recipientKey, lists{kt: []string{"urn:x"}}, xmlsec.ErrUnsupportedAlgorithm},
		{"no CipherData", covParse(t, covEK(kt, good, ``)), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"CipherReference", covParse(t, covEK(kt, good, `<xenc:CipherData><xenc:CipherReference URI="cid:x"/></xenc:CipherData>`)), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"CipherValue not base64", covParse(t, covEK(kt, good, `<xenc:CipherData><xenc:CipherValue>!!</xenc:CipherValue></xenc:CipherData>`)), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"wrong recipient key", reparse(t, ek.Element), other, lists{}, nil},
		{"garbage ciphertext", covParse(t, covEK(kt, good, cd)), recipientKey, lists{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.DecryptEncryptedKey(c.el, c.dec, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: c.allow.kt, AllowedMGFAlgorithms: c.allow.mgf, AllowedDigestAlgorithms: c.allow.digest})
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if key != nil {
				t.Fatal("key returned with an error")
			}
		})
	}
}

func covEM(alg string) string { return `<xenc:EncryptionMethod Algorithm="` + alg + `"/>` }

// SetKeyInfo and AddDataReference compose an EncryptedKey the way a
// WS-Security receiver finds it: KeyInfo after EncryptionMethod, and a
// ReferenceList naming each EncryptedData.
func TestEncryptedKeyComposition(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	str := xmltree.Element(nil, "wsse", "urn:wsse", "SecurityTokenReference")
	str.AddNamespace("wsse", "urn:wsse")
	if err := ek.SetKeyInfo(str); err != nil {
		t.Fatal(err)
	}
	if ek.AddDataReference("ED-1") != nil || ek.AddDataReference("ED-2") != nil {
		t.Fatal("AddDataReference")
	}

	var order []string
	for _, k := range ek.Element.ChildElements() {
		order = append(order, k.Name.Local)
	}
	if got := strings.Join(order, ","); got != "EncryptionMethod,KeyInfo,CipherData,ReferenceList" {
		t.Fatalf("child order %s", got)
	}
	refs := ek.Element.ChildElements()[3].ChildElements()
	if len(refs) != 2 || refs[1].AttrValue("URI") != "#ED-2" {
		t.Fatalf("references %d", len(refs))
	}
	// Still unwraps: KeyInfo and ReferenceList do not disturb decryption.
	if _, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, xenc.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}

	for name, el := range map[string]*xdm.Node{
		"nil":            nil,
		"text node":      {Kind: xdm.KindText, Value: "x"},
		"already placed": ek.Element.ChildElements()[0],
		"second KeyInfo": xmltree.Element(nil, "x", "urn:x", "Other"),
	} {
		if err := ek.SetKeyInfo(el); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDataID(t *testing.T) {
	opts := as4Opts(t)
	opts.DataID = "ED-9"
	key := make([]byte, 16)
	_, ed, err := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a", Body: []byte("b")}, key, xmlsec.TransformAttachmentContentOnly, opts)
	if err != nil || ed.AttrValue("Id") != "ED-9" {
		t.Fatalf("attachment: %v", err)
	}
	tree, err := xmlsec.Parse([]byte(`<r><a/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := xenc.EncryptElement(tree.Root, xmltree.DocumentElement(tree.Root).ChildElements()[0], key, opts)
	if err != nil || !strings.Contains(string(out), `Id="ED-9"`) {
		t.Fatalf("element: %v\n%s", err, out)
	}
}

// ecDecrypter is a crypto.Decrypter whose public key is not RSA.
type ecDecrypter struct{ pub any }

func (d ecDecrypter) Public() crypto.PublicKey { return d.pub }
func (d ecDecrypter) Decrypt(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
	return nil, errors.New("unreachable")
}

func TestDecryptEncryptedKeyMethod(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	good := string(b)
	const dm = `<ds:DigestMethod xmlns:ds="` + xmlsec.NSDSig + `" Algorithm="` + xmlsec.DigestSHA256 + `"></ds:DigestMethod>`
	const mgf = `<xenc11:MGF xmlns:xenc11="` + xmlsec.NSXEnc11 + `" Algorithm="` + xmlsec.MGF1SHA256 + `"></xenc11:MGF>`
	if !strings.Contains(good, dm) || !strings.Contains(good, mgf) {
		t.Fatalf("method:\n%s", good)
	}
	edit := func(old, new string) *xdm.Node { return covParse(t, strings.Replace(good, old, new, 1)) }

	// Section 3.2: KeySize is always permitted and, for RSA-OAEP, must be
	// the modulus size of the decrypting key.
	for _, ks := range []string{"2048", " 2048\n"} {
		if key, err := xenc.DecryptEncryptedKey(edit(dm, `<xenc:KeySize>`+ks+`</xenc:KeySize>`+dm), recipientKey, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, ek.SessionKey) {
			t.Fatalf("KeySize %q: %v", ks, err)
		}
	}
	// XML Encryption's own SHA-384 URI is accepted as the OAEP digest.
	opts := as4Opts(t)
	opts.DigestAlgorithm = xmlsec.DigestSHA384
	ek384, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = c14n.Bytes(ek384.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	alias := covParse(t, strings.Replace(string(b), xmlsec.DigestSHA384, xmlsec.DigestSHA384XMLEnc, 1))
	for _, list := range [][]string{nil, {xmlsec.DigestSHA384XMLEnc}} {
		if key, err := xenc.DecryptEncryptedKey(alias, recipientKey, xenc.DecryptOptions{AllowedDigestAlgorithms: list}); err != nil || !bytes.Equal(key, ek384.SessionKey) {
			t.Fatalf("xmlenc#sha384 %v: %v", list, err)
		}
	}
	if _, err := xenc.DecryptEncryptedKey(alias, recipientKey, xenc.DecryptOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA384}}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("aliases are distinct allow-list entries: %v", err)
	}

	for _, c := range []struct {
		name  string
		el    *xdm.Node
		dec   crypto.Decrypter
		lists [3][]string
		want  error
	}{
		{"KeySize of the session key", edit(dm, `<xenc:KeySize>128</xenc:KeySize>`+dm), recipientKey, [3][]string{}, xmlsec.ErrMalformed},
		{"DigestMethod twice", edit(dm, dm+dm), recipientKey, [3][]string{}, xmlsec.ErrMalformed},
		{"MGF twice", edit(mgf, mgf+mgf), recipientKey, [3][]string{}, xmlsec.ErrMalformed},
		{"unknown child", edit(dm, `<x:Y xmlns:x="urn:x"/>`+dm), recipientKey, [3][]string{}, xmlsec.ErrMalformed},
		// rsa-1_5 has no MGF; it is refused as the algorithm it is, not as
		// an implicit SHA-1.
		{"rsa-1_5", edit(xmlsec.KeyTransportRSAOAEP, "http://www.w3.org/2001/04/xmlenc#rsa-1_5"), recipientKey, [3][]string{}, xmlsec.ErrAlgorithmNotAllowed},
		{"non-RSA key", covParse(t, good), ecDecrypter{pub: "x"}, [3][]string{}, xmlsec.ErrUnsupportedAlgorithm},
		{"allow-listed unimplemented MGF", edit(xmlsec.MGF1SHA256, "urn:x"), recipientKey, [3][]string{1: {"urn:x"}}, xmlsec.ErrUnsupportedAlgorithm},
		{"allow-listed unimplemented digest", edit(xmlsec.DigestSHA256, "urn:x"), recipientKey, [3][]string{2: {"urn:x"}}, xmlsec.ErrUnsupportedAlgorithm},
		{"SHA-1 digest", edit(xmlsec.DigestSHA256, "http://www.w3.org/2000/09/xmldsig#sha1"), recipientKey, [3][]string{}, xmlsec.ErrAlgorithmNotAllowed},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.DecryptEncryptedKey(c.el, c.dec, xenc.DecryptOptions{AllowedKeyTransportAlgorithms: c.lists[0], AllowedMGFAlgorithms: c.lists[1], AllowedDigestAlgorithms: c.lists[2]})
			if !errors.Is(err, c.want) || key != nil {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.name == "rsa-1_5" && !strings.Contains(err.Error(), "key transport") {
				t.Fatalf("reported as %v", err)
			}
		})
	}
}

// Section 5.5.2: MGF1 with SHA-224 is produced when named, and accepted
// only when named.
func TestMGF1SHA224(t *testing.T) {
	opts := as4Opts(t)
	opts.MGFAlgorithm = xmlsec.MGF1SHA224
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	el := reparse(t, ek.Element)
	if _, err := xenc.DecryptEncryptedKey(el, recipientKey, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("default set: %v", err)
	}
	key, err := xenc.DecryptEncryptedKey(el, recipientKey, xenc.DecryptOptions{AllowedMGFAlgorithms: []string{xmlsec.MGF1SHA224}})
	if err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("named: %v", err)
	}
}

// An RSA-OAEP EncryptedKey's ciphertext by external CipherReference.
func TestDecryptEncryptedKeyCipherReference(t *testing.T) {
	ek, err := xenc.GenerateEncryptedKey(as4Opts(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	cv := firstNamed(ek.Element, "CipherValue").StringValue()
	doc := strings.Replace(string(s), `<xenc:CipherValue>`+cv+`</xenc:CipherValue>`, `<xenc:CipherReference URI="http://example.com/k"></xenc:CipherReference>`, 1)
	wrapped, _ := base64.StdEncoding.DecodeString(cv)
	key, err := xenc.DecryptEncryptedKey(covParse(t, doc), recipientKey, xenc.DecryptOptions{ResolveURI: func(string) ([]byte, error) { return wrapped, nil }})
	if err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatalf("%v", err)
	}
}

// A nil or zero-value EncryptedKey, or one whose Element is not an
// xenc:EncryptedKey, is an error from every method, never a panic.
func TestEncryptedKeyMethodsNilReceiver(t *testing.T) {
	for name, ek := range map[string]*xenc.EncryptedKey{
		"nil":           nil,
		"zero":          {},
		"other element": {Element: xmltree.Element(nil, "", "", "x")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ek.AddDataReference("d"); err == nil {
				t.Fatal("AddDataReference")
			}
			if err := ek.AddKeyReference("k"); err == nil {
				t.Fatal("AddKeyReference")
			}
			if err := ek.SetKeyInfo(xmltree.Element(nil, "ds", xmlsec.NSDSig, "KeyName")); err == nil {
				t.Fatal("SetKeyInfo")
			}
		})
	}
}

// An option with no effect on the EncryptedKey made, or contradicting it,
// is refused rather than ignored.
func TestGenerateEncryptedKeyInapplicableOptions(t *testing.T) {
	kek := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: make([]byte, 16)}
	pw := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, Password: []byte("pw"), PBKDF2Iterations: xenc.MinPBKDF2Iterations}
	ec := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128).opts
	for name, c := range map[string]struct {
		base xenc.EncryptOptions
		mod  func(*xenc.EncryptOptions)
	}{
		"KEK, MGFAlgorithm":               {kek, func(o *xenc.EncryptOptions) { o.MGFAlgorithm = xmlsec.MGF1SHA256 }},
		"KEK, OAEPParams":                 {kek, func(o *xenc.EncryptOptions) { o.OAEPParams = []byte("l") }},
		"KEK, DigestAlgorithm":            {kek, func(o *xenc.EncryptOptions) { o.DigestAlgorithm = xmlsec.DigestSHA256 }},
		"KEK, KeyAgreementAlgorithm":      {kek, func(o *xenc.EncryptOptions) { o.KeyAgreementAlgorithm = xmlsec.KeyAgreementECDHES }},
		"KEK, RecipientKeyName":           {kek, func(o *xenc.EncryptOptions) { o.RecipientKeyName = "r" }},
		"KEK, DirectKeyAgreement":         {kek, func(o *xenc.EncryptOptions) { o.DirectKeyAgreement = true }},
		"KEK, MasterKey":                  {kek, func(o *xenc.EncryptOptions) { o.MasterKey = make([]byte, 32) }},
		"KEK, PBKDF2Iterations":           {kek, func(o *xenc.EncryptOptions) { o.PBKDF2Iterations = xenc.MinPBKDF2Iterations }},
		"Password, DigestAlgorithm":       {pw, func(o *xenc.EncryptOptions) { o.DigestAlgorithm = xmlsec.DigestSHA256 }},
		"Password, 999 iterations":        {pw, func(o *xenc.EncryptOptions) { o.PBKDF2Iterations = 999 }},
		"ECDH-ES, MGFAlgorithm":           {ec, func(o *xenc.EncryptOptions) { o.MGFAlgorithm = xmlsec.MGF1SHA256 }},
		"ECDH-ES, RecipientKeyName":       {ec, func(o *xenc.EncryptOptions) { o.RecipientKeyName = "r" }},
		"RSA-OAEP, KeyEncryptionKey":      {as4Opts(t), func(o *xenc.EncryptOptions) { o.KeyEncryptionKey = make([]byte, 16) }},
		"RSA-OAEP, Password":              {as4Opts(t), func(o *xenc.EncryptOptions) { o.Password = []byte("pw") }},
		"RSA-OAEP, RecipientDH":           {as4Opts(t), func(o *xenc.EncryptOptions) { o.RecipientDH = &xenc.DHPublicKey{} }},
		"RSA-OAEP no Recipient, KEK":      {as4Opts(t), func(o *xenc.EncryptOptions) { o.Recipient, o.KeyEncryptionKey = nil, make([]byte, 16) }},
		"RSA-OAEP, KeyAgreementAlgorithm": {as4Opts(t), func(o *xenc.EncryptOptions) { o.KeyAgreementAlgorithm = xmlsec.KeyAgreementECDHES }},
	} {
		t.Run(name, func(t *testing.T) {
			opts := c.base
			c.mod(&opts)
			if ek, err := xenc.GenerateEncryptedKey(opts); err == nil || ek != nil {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// The data side refuses an iteration count without a Password too.
	doc := covParse(t, `<r><a>x</a></r>`)
	if _, err := xenc.EncryptElement(doc, doc.ChildElements()[0], make([]byte, 16), xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, PBKDF2Iterations: xenc.MinPBKDF2Iterations}); err == nil {
		t.Fatal("PBKDF2Iterations without Password accepted")
	}
}
