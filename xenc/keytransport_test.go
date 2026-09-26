package xenc_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

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
	key, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, nil, nil, nil)
	if err != nil || !bytes.Equal(key, opts.SessionKey) {
		t.Fatalf("unwrapped %x, %v", key, err)
	}
}

// covEK is an xenc:EncryptedKey with the given EncryptionMethod content and
// trailing content.
func covEK(alg, method, rest string) string {
	return `<xenc:EncryptedKey xmlns:xenc="` + xenc.NSXEnc + `" xmlns:xenc11="` + xenc.NSXEnc11 + `" xmlns:ds="` + xenc.NSDSig + `">` +
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
		{"not an EncryptedKey", covParse(t, `<xenc:EncryptedData xmlns:xenc="`+xenc.NSXEnc+`"/>`), recipientKey, lists{}, xmlsec.ErrMalformed},
		{"no EncryptionMethod", covParse(t, `<xenc:EncryptedKey xmlns:xenc="`+xenc.NSXEnc+`">`+cd+`</xenc:EncryptedKey>`), recipientKey, lists{}, xmlsec.ErrMalformed},
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
			key, err := xenc.DecryptEncryptedKey(c.el, c.dec, c.allow.kt, c.allow.mgf, c.allow.digest)
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
	ek.AddDataReference("ED-1")
	ek.AddDataReference("ED-2")

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
	if _, err := xenc.DecryptEncryptedKey(reparse(t, ek.Element), recipientKey, nil, nil, nil); err != nil {
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
