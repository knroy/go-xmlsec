package xenc_test

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

const dkDoc = `<r xmlns="urn:example"><p>hello</p></r>`

// dkEncrypt encrypts the p element of dkDoc with no session key, under
// the key opts' KeyInfo conveys, and returns the parsed result's
// EncryptedData.
func dkEncrypt(t *testing.T, opts xenc.EncryptOptions) *xdm.Node {
	t.Helper()
	doc := covParse(t, dkDoc)
	out, err := xenc.EncryptElement(doc.Root(), firstNamed(doc, "p"), nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return firstNamed(covParse(t, string(out)), "EncryptedData")
}

func dkString(t *testing.T, n *xdm.Node) string {
	t.Helper()
	b, err := c14n.Bytes(n, c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Section 3.5.2: a data key derived from a master key by ConcatKDF, named
// by an xenc11:DerivedKey in the EncryptedData's KeyInfo.
func TestMasterKeyRoundTrip(t *testing.T) {
	master := bytes.Repeat([]byte{9}, 32)
	opts := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES256GCM, DigestAlgorithm: xmlsec.DigestSHA256,
		MasterKey: master, DerivedKeyName: "dk", MasterKeyName: "Our other secret"}
	ed := dkEncrypt(t, opts)
	s := dkString(t, ed)
	for _, want := range []string{
		`<ds:KeyInfo xmlns:ds="` + xmlsec.NSDSig + `"><xenc11:DerivedKey xmlns:xenc11="` + xmlsec.NSXEnc11 + `"><xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationConcatKDF + `">`,
		`PartyUInfo="00`,
		`<xenc11:DerivedKeyName>dk</xenc11:DerivedKeyName><xenc11:MasterKeyName>Our other secret</xenc11:MasterKeyName></xenc11:DerivedKey></ds:KeyInfo><xenc:CipherData>`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("no %s in\n%s", want, s)
		}
	}
	dk, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil || !strings.Contains(string(pt), ">hello</p>") {
		t.Fatalf("%q, %v", pt, err)
	}
	// A fresh PartyUInfo each time: no two derived keys are the same.
	ed2 := dkEncrypt(t, opts)
	dk2, err := xenc.FindDerivedKey(ed2)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := xenc.DeriveKey(dk2, ed2, master, xenc.DecryptOptions{})
	if err != nil || bytes.Equal(key, key2) {
		t.Fatalf("same derived key twice: %v", err)
	}
	// The master key is the caller's: another derives another key.
	other, _ := xenc.DeriveKey(dk, ed, bytes.Repeat([]byte{8}, 32), xenc.DecryptOptions{})
	if _, err := xenc.DecryptData(ed, other, xenc.DecryptOptions{}); err == nil {
		t.Fatal("decrypted under another master key")
	}
}

// PBKDF2 directly on an EncryptedData: Password with no session key.
func TestPasswordDataKey(t *testing.T) {
	pw := []byte("correct horse battery staple")
	ed := dkEncrypt(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, Password: pw, PBKDF2Iterations: xenc.MinPBKDF2Iterations})
	dk, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xenc.DeriveKey(dk, ed, pw, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("PBKDF2 not named: %v", err)
	}
	key, err := xenc.DeriveKey(dk, ed, pw, xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}

// A DerivedKey whose ReferenceList names an EncryptedKey (spec Example 25,
// with a KeyReference and byte-aligned ConcatKDF parameters): the derived
// key is that EncryptedKey's KEK.
func TestDeriveKeyForEncryptedKey(t *testing.T) {
	master := []byte("Our other secret, 16+ octets")
	doc := `<r xmlns:xenc="` + xmlsec.NSXEnc + `" xmlns:xenc11="` + xmlsec.NSXEnc11 + `" xmlns:ds="` + xmlsec.NSDSig + `">` +
		`<xenc11:DerivedKey><xenc11:KeyDerivationMethod Algorithm="` + xmlsec.KeyDerivationConcatKDF + `">` +
		`<xenc11:ConcatKDFParams AlgorithmID="0000" PartyUInfo="00D8" PartyVInfo="00D0"><ds:DigestMethod Algorithm="` + xmlsec.DigestSHA256 + `"/></xenc11:ConcatKDFParams>` +
		`</xenc11:KeyDerivationMethod><xenc:ReferenceList><xenc:KeyReference URI="#EK"/></xenc:ReferenceList>` +
		`<xenc11:MasterKeyName>Our other secret</xenc11:MasterKeyName></xenc11:DerivedKey>` +
		`<xenc:EncryptedKey Id="EK"><xenc:EncryptionMethod Algorithm="` + xmlsec.KeyWrapAES128 + `"/><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></r>`
	root := covParse(t, doc)
	ek := firstNamed(root, "EncryptedKey")
	dk, err := xenc.FindDerivedKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := xenc.DeriveKey(dk, ek, master, xenc.DecryptOptions{})
	if err != nil || len(kek) != 16 {
		t.Fatalf("%x, %v", kek, err)
	}
	// Wrap a session key under that KEK, and unwrap it in the document.
	gen, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, KeyTransportAlgorithm: xmlsec.KeyWrapAES128, KeyEncryptionKey: kek})
	if err != nil {
		t.Fatal(err)
	}
	doc = strings.Replace(doc, `<xenc:CipherValue>AA==`, `<xenc:CipherValue>`+firstNamed(gen.Element, "CipherValue").StringValue(), 1)
	ek = firstNamed(covParse(t, doc), "EncryptedKey")
	if key, err := xenc.UnwrapEncryptedKey(ek, kek, xenc.DecryptOptions{}); err != nil || !bytes.Equal(key, gen.SessionKey) {
		t.Fatalf("unwrap: %v", err)
	}
	// Example 25's own PartyUInfo "03D8" is a bit string of 5 bits, which
	// makes OtherInfo 21 bits, which ConcatKDF over octets cannot hash.
	doc = strings.Replace(doc, `PartyUInfo="00D8"`, `PartyUInfo="03D8"`, 1)
	ek = firstNamed(covParse(t, doc), "EncryptedKey")
	dk, _ = xenc.FindDerivedKey(ek)
	if _, err := xenc.DeriveKey(dk, ek, master, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrUnsupportedAlgorithm) {
		t.Fatalf("padded bit string: %v", err)
	}
}

func TestDeriveKeyErrors(t *testing.T) {
	master := bytes.Repeat([]byte{9}, 32)
	ed := dkEncrypt(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256, MasterKey: master})
	good, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	gs := dkString(t, good)
	edit := func(old, new string) *xdm.Node {
		if !strings.Contains(gs, old) {
			t.Fatalf("no %s", old)
		}
		return covParse(t, strings.Replace(gs, old, new, 1))
	}
	ek := covParse(t, kwEK(xmlsec.KeyWrapAES256, ``, kwCV(make([]byte, 40))))
	for _, c := range []struct {
		name       string
		dk, target *xdm.Node
		master     []byte
		opts       xenc.DecryptOptions
		want       error // nil: any error
	}{
		{"no target", good, nil, master, xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"data outside allow-list", good, ed, master, xenc.DecryptOptions{AllowedDataAlgorithms: []string{xmlsec.EncAES256GCM}}, xmlsec.ErrAlgorithmNotAllowed},
		{"wrap outside allow-list", good, ek, master, xenc.DecryptOptions{AllowedKeyWrapAlgorithms: []string{xmlsec.KeyWrapAES128}}, xmlsec.ErrAlgorithmNotAllowed},
		{"not a DerivedKey", ed, ed, master, xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"nil DerivedKey", nil, ed, master, xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"unexpected child", edit(`<xenc11:KeyDerivationMethod`, `<xenc11:Other/><xenc11:KeyDerivationMethod`), ed, master, xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"no KeyDerivationMethod", covParse(t, `<xenc11:DerivedKey xmlns:xenc11="`+xmlsec.NSXEnc11+`"><xenc11:MasterKeyName>m</xenc11:MasterKeyName></xenc11:DerivedKey>`), ed, master, xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		{"KDF outside allow-list", good, ed, master, xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}, xmlsec.ErrAlgorithmNotAllowed},
		{"digest outside allow-list", good, ed, master, xenc.DecryptOptions{AllowedDigestAlgorithms: []string{xmlsec.DigestSHA512}}, xmlsec.ErrAlgorithmNotAllowed},
		{"no master key", good, ed, nil, xenc.DecryptOptions{}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.DeriveKey(c.dk, c.target, c.master, c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) || key != nil {
				t.Fatalf("got %x, %v; want %v", key, err, c.want)
			}
		})
	}
	// The schema's ReferenceList and names are accepted beside the method.
	named := edit(`</xenc11:KeyDerivationMethod>`, `</xenc11:KeyDerivationMethod><xenc:ReferenceList xmlns:xenc="`+xmlsec.NSXEnc+`"/><xenc11:DerivedKeyName>d</xenc11:DerivedKeyName>`)
	if _, err := xenc.DeriveKey(named, ed, master, xenc.DecryptOptions{}); err != nil {
		t.Fatal(err)
	}
}

// The key an EncryptedData's KeyInfo conveys is used only with no session
// key, and only one of MasterKey, DirectKeyAgreement and Password.
func TestDataKeyOptionErrors(t *testing.T) {
	ec := newECRecipient(t, elliptic.P256(), xmlsec.KeyWrapAES128)
	dh := dhKey(t, ffdhe2048)
	master := bytes.Repeat([]byte{9}, 32)
	base := xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256}
	for _, c := range []struct {
		name string
		key  []byte
		mod  func(*xenc.EncryptOptions)
		want error // nil: any error
	}{
		{"session key and MasterKey", make([]byte, 16), func(o *xenc.EncryptOptions) { o.MasterKey = master }, nil},
		{"session key and DirectKeyAgreement", make([]byte, 16), func(o *xenc.EncryptOptions) { o.DirectKeyAgreement = true }, nil},
		{"MasterKey and Password", nil, func(o *xenc.EncryptOptions) { o.MasterKey, o.Password = master, []byte("pw") }, nil},
		{"CBC", nil, func(o *xenc.EncryptOptions) { o.MasterKey, o.DataAlgorithm = master, xmlsec.EncAES128CBC }, xmlsec.ErrUnsupportedAlgorithm},
		{"SHA-1 digest", nil, func(o *xenc.EncryptOptions) { o.MasterKey, o.DigestAlgorithm = master, xmlsec.DigestSHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown data algorithm", nil, func(o *xenc.EncryptOptions) { o.MasterKey, o.DataAlgorithm = master, "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"unknown digest", nil, func(o *xenc.EncryptOptions) { o.MasterKey, o.DigestAlgorithm = master, "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		{"short MasterKey", nil, func(o *xenc.EncryptOptions) { o.MasterKey = master[:15] }, nil},
		{"DirectKeyAgreement without recipient", nil, func(o *xenc.EncryptOptions) { o.DirectKeyAgreement = true }, nil},
		{"DirectKeyAgreement with both recipients", nil, func(o *xenc.EncryptOptions) {
			o.DirectKeyAgreement, o.Recipient, o.RecipientDH = true, ec.opts.Recipient, &dh.DHPublicKey
		}, nil},
		{"no key at all", nil, func(*xenc.EncryptOptions) {}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			opts := base
			c.mod(&opts)
			doc := covParse(t, dkDoc)
			out, err := xenc.EncryptElement(doc.Root(), firstNamed(doc, "p"), c.key, opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) || out != nil {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			_, ed, err := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a", Body: []byte("b")}, c.key, xmlsec.TransformAttachmentContentOnly, opts)
			if err == nil || ed != nil {
				t.Fatalf("attachment: %v", err)
			}
		})
	}
}

// An attachment's EncryptedData can carry the DerivedKey too.
func TestMasterKeyAttachment(t *testing.T) {
	master := bytes.Repeat([]byte{9}, 16)
	ct, ed, err := xenc.EncryptAttachment(&xmlsec.Attachment{ID: "a", Body: []byte("body")}, nil, xmlsec.TransformAttachmentContentOnly,
		xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256, MasterKey: master})
	if err != nil {
		t.Fatal(err)
	}
	ed = covParse(t, dkString(t, ed))
	dk, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	key, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	att, err := xenc.DecryptAttachment(ed, ct, key, xenc.DecryptOptions{})
	if err != nil || string(att.Body) != "body" {
		t.Fatalf("%v", err)
	}
}

// Section 3.5.2: a DerivedKey without KeyDerivationMethod is derived by
// the one the recipient knows, DecryptOptions.ImpliedKeyDerivationMethod,
// under the same allow-lists; one the DerivedKey has always wins.
func TestImpliedKeyDerivationMethod(t *testing.T) {
	master := bytes.Repeat([]byte{9}, 32)
	ed := dkEncrypt(t, xenc.EncryptOptions{DataAlgorithm: xmlsec.EncAES128GCM, DigestAlgorithm: xmlsec.DigestSHA256, MasterKey: master})
	dk, err := xenc.FindDerivedKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	want, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	kdm := firstNamed(dk, "KeyDerivationMethod")
	bare := covParse(t, `<xenc11:DerivedKey xmlns:xenc11="`+xmlsec.NSXEnc11+`"><xenc11:MasterKeyName>m</xenc11:MasterKeyName></xenc11:DerivedKey>`)
	implied := xenc.DecryptOptions{ImpliedKeyDerivationMethod: kdm}
	if got, err := xenc.DeriveKey(bare, ed, master, implied); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("implied: %x, %v", got, err)
	}
	other := covParse(t, strings.Replace(dkString(t, kdm), xmlsec.DigestSHA256, xmlsec.DigestSHA512, 1))
	if got, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{ImpliedKeyDerivationMethod: other}); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("explicit beside implied: %x, %v", got, err)
	}
	for name, c := range map[string]struct {
		opts xenc.DecryptOptions
		want error // nil: any error
	}{
		"none":               {xenc.DecryptOptions{}, xmlsec.ErrMalformed},
		"not a method":       {xenc.DecryptOptions{ImpliedKeyDerivationMethod: bare}, nil},
		"outside allow-list": {xenc.DecryptOptions{ImpliedKeyDerivationMethod: kdm, AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}, xmlsec.ErrAlgorithmNotAllowed},
	} {
		if key, err := xenc.DeriveKey(bare, ed, master, c.opts); err == nil || c.want != nil && !errors.Is(err, c.want) || key != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
