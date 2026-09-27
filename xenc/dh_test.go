package xenc_test

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/xenc"
)

func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(strings.Join(strings.Fields(s), ""), 16)
	if !ok {
		panic(s)
	}
	return n
}

// The safe-prime groups of RFC 3526 section 3 (MODP group 14) and RFC 7919
// appendix A.1 (ffdhe2048), both with generator 2 and Q = (P-1)/2.
var (
	modp2048 = hexInt(`FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF`)
	ffdhe2048 = hexInt(`FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 61285C97 FFFFFFFF FFFFFFFF`)
	ffdhe2048Q = hexInt(`7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
    EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
    BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
    9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
    CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
    98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
    DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
    8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
    C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
    9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
    4435A11C 30942E4B FFFFFFFF FFFFFFFF`)
	two = big.NewInt(2)
)

// safeQ is (p-1)/2.
func safeQ(p *big.Int) *big.Int { return new(big.Int).Rsh(p, 1) }

func dhKey(t *testing.T, p *big.Int) *xenc.DHPrivateKey {
	t.Helper()
	k, err := xenc.GenerateDHKey(p, safeQ(p), two)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func dhOpts(k *xenc.DHPrivateKey, agreement, wrap, digest string) xenc.EncryptOptions {
	return xenc.EncryptOptions{
		DataAlgorithm:         xmlsec.EncAES128GCM,
		KeyTransportAlgorithm: wrap,
		KeyAgreementAlgorithm: agreement,
		DigestAlgorithm:       digest,
		RecipientDH:           &k.DHPublicKey,
	}
}

func dhAllow(agreement string) xenc.DecryptOptions {
	return xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{agreement}}
}

// The RFC 7919 Q is (P-1)/2, as the groups' construction says.
func TestDHGroupFixtures(t *testing.T) {
	if safeQ(ffdhe2048).Cmp(ffdhe2048Q) != 0 {
		t.Fatal("ffdhe2048 Q is not (P-1)/2")
	}
	for _, p := range []*big.Int{modp2048, ffdhe2048} {
		if p.BitLen() != 2048 || !p.ProbablyPrime(20) || !safeQ(p).ProbablyPrime(20) {
			t.Fatal("not a 2048-bit safe prime")
		}
	}
}

// dh-es with ConcatKDF and dh with the Legacy KDF, in both groups, each
// wrap size and digest.
func TestDHRoundTrip(t *testing.T) {
	for _, c := range []struct {
		name, agreement, wrap, digest string
		p                             *big.Int
	}{
		{"dh-es ffdhe2048", xmlsec.KeyAgreementDHES, xmlsec.KeyWrapAES128, xmlsec.DigestSHA256, ffdhe2048},
		{"dh-es modp2048", xmlsec.KeyAgreementDHES, xmlsec.KeyWrapAES256, xmlsec.DigestSHA512, modp2048},
		{"dh ffdhe2048", xmlsec.KeyAgreementDH, xmlsec.KeyWrapAES192, xmlsec.DigestSHA384, ffdhe2048},
		{"dh modp2048", xmlsec.KeyAgreementDH, xmlsec.KeyWrapAES256, xmlsec.DigestSHA256, modp2048},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := dhKey(t, c.p)
			ek, err := xenc.GenerateEncryptedKey(dhOpts(k, c.agreement, c.wrap, c.digest))
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
			for _, want := range []string{
				`<xenc:AgreementMethod Algorithm="` + c.agreement + `">`,
				`<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue><xenc:P>`,
				`</xenc:Generator><xenc:Public>`,
				`<xenc:RecipientKeyInfo><ds:KeyValue><xenc:DHKeyValue><xenc:Public>` + base64.StdEncoding.EncodeToString(k.Y.Bytes()) + `</xenc:Public>`,
			} {
				if !strings.Contains(string(b), want) {
					t.Fatalf("no %s in\n%s", want, b)
				}
			}
			if strings.Contains(string(b), "KeyDerivationMethod") != (c.agreement == xmlsec.KeyAgreementDHES) {
				t.Fatalf("KeyDerivationMethod presence wrong for %s:\n%s", c.agreement, b)
			}
			opts := dhAllow(c.agreement)
			opts.AllowedDigestAlgorithms = []string{c.digest}
			opts.AllowedKeyWrapAlgorithms = []string{c.wrap}
			key, err := xenc.DecryptAgreedKeyDH(reparse(t, ek.Element), k, opts)
			if err != nil || !bytes.Equal(key, ek.SessionKey) {
				t.Fatalf("agreed %x, %v", key, err)
			}
			// Another key in the same group agrees on another KEK.
			if _, err := xenc.DecryptAgreedKeyDH(reparse(t, ek.Element), dhKey(t, c.p), opts); err == nil {
				t.Fatal("another recipient unwrapped the key")
			}
		})
	}
}

// RecipientKeyName names the recipient's key in RecipientKeyInfo, as
// xmlsec1 needs to find it, in place of its public value.
func TestDHRecipientKeyName(t *testing.T) {
	k := dhKey(t, ffdhe2048)
	opts := dhOpts(k, xmlsec.KeyAgreementDHES, xmlsec.KeyWrapAES128, xmlsec.DigestSHA256)
	opts.RecipientKeyName = "recipient"
	ek, err := xenc.GenerateEncryptedKey(opts)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	if !strings.Contains(string(b), `<xenc:RecipientKeyInfo><ds:KeyName>recipient</ds:KeyName></xenc:RecipientKeyInfo>`) {
		t.Fatalf("no KeyName in\n%s", b)
	}
	if key, err := xenc.DecryptAgreedKeyDH(reparse(t, ek.Element), k, dhAllow(xmlsec.KeyAgreementDHES)); err != nil || !bytes.Equal(key, ek.SessionKey) {
		t.Fatal(err)
	}
}

// Section 5.6.2.2: KM(counter) = DigestAlg(ZZ | counter | EncryptionAlg |
// KA-Nonce | KeySize), counter as two upper-case hex digits. The input is
// section 5.6.2.2's own example (Example 40: ZZ 0xDEADBEEF, "Example:
// Block/Alg", KA-Nonce "foo", 80 bits); the expected values are SHA-1 and
// SHA-256 of those octets, computed independently with Python's hashlib.
// Example 41's printed value, 534C9B8C..., is not the SHA-1 of Example
// 40's octets, which hash to 59D9BA5E...
func TestLegacyKDFKnownAnswers(t *testing.T) {
	zz, _ := hex.DecodeString("DEADBEEF")
	for _, c := range []struct {
		h       crypto.Hash
		alg     string
		nonce   string
		size    int
		wantHex string
	}{
		{crypto.SHA1, "Example:Block/Alg", "foo", 10, "59d9ba5e06072c119409"},
		// Two blocks: KM(1) | KM(2) truncated.
		{crypto.SHA1, xmlsec.KeyWrapAES256, "foo", 32, "0a6ccef003f980eccec717dd6d11b292245d57a8a90e5fe430d2da79b0a75520"},
		{crypto.SHA256, xmlsec.KeyWrapAES256, "", 32, "ae5f56c09667593210c1910564a61a6f45a42583651dbcb0f652620acfe52a58"},
	} {
		got := xenc.LegacyKDF(c.h, zz, c.alg, []byte(c.nonce), c.size)
		if hex.EncodeToString(got) != c.wantHex {
			t.Errorf("%v %s: %x, want %s", c.h, c.alg, got, c.wantHex)
		}
	}
}

func TestGenerateDHKeyErrors(t *testing.T) {
	q := safeQ(ffdhe2048)
	pm1 := new(big.Int).Sub(ffdhe2048, big.NewInt(1))
	composite := new(big.Int).Add(new(big.Int).Lsh(q, 2), big.NewInt(1)) // 4Q+1: Q divides it less one
	for name, g := range map[string][3]*big.Int{
		"no P":               {nil, q, two},
		"1024-bit P":         {new(big.Int).Rsh(ffdhe2048, 1024), q, two},
		"8193-bit P":         {new(big.Int).Lsh(ffdhe2048, 6145), q, two},
		"Q not dividing":     {ffdhe2048, new(big.Int).Sub(q, two), two},
		"small Q":            {ffdhe2048, two, two},
		"composite P":        {composite, q, two},
		"generator 1":        {ffdhe2048, q, big.NewInt(1)},
		"generator P-1":      {ffdhe2048, q, pm1},
		"generator order 2Q": {ffdhe2048, q, nonResidue(t, ffdhe2048)},
	} {
		t.Run(name, func(t *testing.T) {
			if composite.ProbablyPrime(20) {
				t.Fatal("4Q+1 is prime; pick another composite")
			}
			if _, err := xenc.GenerateDHKey(g[0], g[1], g[2]); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// nonResidue returns the least g > 1 outside the order-Q subgroup of the
// safe prime p: a generator of the whole group.
func nonResidue(t *testing.T, p *big.Int) *big.Int {
	t.Helper()
	for g := big.NewInt(3); ; g.Add(g, big.NewInt(1)) {
		if new(big.Int).Exp(g, safeQ(p), p).Cmp(big.NewInt(1)) != 0 {
			return g
		}
	}
}

func TestGenerateDHAgreedKeyErrors(t *testing.T) {
	k := dhKey(t, ffdhe2048)
	for name, c := range map[string]struct {
		mod  func(*xenc.EncryptOptions)
		want error
	}{
		"ECDH-ES with a DH key": {func(o *xenc.EncryptOptions) { o.KeyAgreementAlgorithm = xmlsec.KeyAgreementECDHES }, xmlsec.ErrUnsupportedAlgorithm},
		"unknown digest":        {func(o *xenc.EncryptOptions) { o.DigestAlgorithm = "urn:x" }, xmlsec.ErrUnsupportedAlgorithm},
		"SHA-1 digest":          {func(o *xenc.EncryptOptions) { o.DigestAlgorithm = xmlsec.DigestSHA1 }, xmlsec.ErrUnsupportedAlgorithm},
		"1024-bit group": {func(o *xenc.EncryptOptions) {
			o.RecipientDH = &xenc.DHPublicKey{P: new(big.Int).Rsh(ffdhe2048, 1024), Q: k.Q, G: k.G, Y: k.Y}
		}, xmlsec.ErrUnsupportedKeyInfo},
		"no public value": {func(o *xenc.EncryptOptions) { o.RecipientDH = &xenc.DHPublicKey{P: k.P, Q: k.Q, G: k.G} }, xmlsec.ErrUnsupportedKeyInfo},
		"public value 1": {func(o *xenc.EncryptOptions) {
			o.RecipientDH = &xenc.DHPublicKey{P: k.P, Q: k.Q, G: k.G, Y: big.NewInt(1)}
		}, xmlsec.ErrUnsupportedKeyInfo},
		"public value outside Q": {func(o *xenc.EncryptOptions) {
			o.RecipientDH = &xenc.DHPublicKey{P: k.P, Q: k.Q, G: k.G, Y: nonResidue(t, k.P)}
		}, xmlsec.ErrUnsupportedKeyInfo},
		"with a KeyEncryptionKey too": {func(o *xenc.EncryptOptions) { o.KeyEncryptionKey = make([]byte, 16) }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			opts := dhOpts(k, xmlsec.KeyAgreementDHES, xmlsec.KeyWrapAES128, xmlsec.DigestSHA256)
			c.mod(&opts)
			_, err := xenc.GenerateEncryptedKey(opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestDecryptAgreedKeyDHErrors(t *testing.T) {
	k := dhKey(t, ffdhe2048)
	gen := func(agreement string) string {
		ek, err := xenc.GenerateEncryptedKey(dhOpts(k, agreement, xmlsec.KeyWrapAES128, xmlsec.DigestSHA256))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
		return string(b)
	}
	es, legacy := gen(xmlsec.KeyAgreementDHES), gen(xmlsec.KeyAgreementDH)
	edit := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("no %s in %s", old, s)
		}
		return strings.Replace(s, old, new, 1)
	}
	cut := func(s, from, to string) string { // removes from..to inclusive
		i, j := strings.Index(s, from), strings.Index(s, to)
		return s[:i] + s[j+len(to):]
	}
	b64 := func(n *big.Int) string { return base64.StdEncoding.EncodeToString(n.Bytes()) }
	// oki replaces the originator's DHKeyValue content.
	oki := func(s, content string) string {
		i := strings.Index(s, `<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue>`) + len(`<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue>`)
		j := i + strings.Index(s[i:], `</xenc:DHKeyValue>`)
		return s[:i] + content + s[j:]
	}
	el := func(local string, n *big.Int) string {
		return `<xenc:` + local + `>` + b64(n) + `</xenc:` + local + `>`
	}
	pm1 := new(big.Int).Sub(k.P, big.NewInt(1))
	other := dhKey(t, modp2048)
	both := xenc.DecryptOptions{AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementDHES, xmlsec.KeyAgreementDH}}
	withDigest := func(o xenc.DecryptOptions, d ...string) xenc.DecryptOptions { o.AllowedDigestAlgorithms = d; return o }
	withDerivation := func(o xenc.DecryptOptions, d ...string) xenc.DecryptOptions {
		o.AllowedKeyDerivationAlgorithms = d
		return o
	}
	withAgreement := func(o xenc.DecryptOptions, a ...string) xenc.DecryptOptions {
		o.AllowedKeyAgreementAlgorithms = a
		return o
	}
	badX := *k
	badX.X = k.Q

	cases := []struct {
		name string
		el   string
		priv *xenc.DHPrivateKey
		opts xenc.DecryptOptions
		want error // nil: any error
	}{
		{"not an EncryptedKey", covED(``, ``), k, both, xmlsec.ErrMalformed},
		{"no private key", es, nil, both, nil},
		{"dh-es not named", es, k, xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed},
		{"dh not named", legacy, k, dhAllow(xmlsec.KeyAgreementDHES), xmlsec.ErrAlgorithmNotAllowed},
		{"ECDH-ES document", edit(es, `Algorithm="`+xmlsec.KeyAgreementDHES+`"`, `Algorithm="`+xmlsec.KeyAgreementECDHES+`"`), k, withAgreement(both, xmlsec.KeyAgreementECDHES), xmlsec.ErrUnsupportedAlgorithm},
		{"dh-es PBKDF2 not named", edit(es, `Algorithm="`+xmlsec.KeyDerivationConcatKDF+`"`, `Algorithm="`+xmlsec.KeyDerivationPBKDF2+`"`), k, both, xmlsec.ErrAlgorithmNotAllowed},
		{"unexpected child", edit(es, `<xenc11:KeyDerivationMethod`, `<ds:KeyName>k</ds:KeyName><xenc11:KeyDerivationMethod`), k, both, xmlsec.ErrMalformed},
		{"two KeyDerivationMethods", edit(es, `<xenc:OriginatorKeyInfo>`, `<xenc11:KeyDerivationMethod xmlns:xenc11="`+xmlsec.NSXEnc11+`"></xenc11:KeyDerivationMethod><xenc:OriginatorKeyInfo>`), k, both, xmlsec.ErrMalformed},
		{"allow-listed unimplemented KDF", edit(es, `Algorithm="`+xmlsec.KeyDerivationConcatKDF+`"`, `Algorithm="urn:x"`), k, withDerivation(both, "urn:x"), xmlsec.ErrUnsupportedAlgorithm},
		{"dh with KeyDerivationMethod", edit(legacy, `<ds:DigestMethod`, `<xenc11:KeyDerivationMethod xmlns:xenc11="`+xmlsec.NSXEnc11+`"></xenc11:KeyDerivationMethod><ds:DigestMethod`), k, both, xmlsec.ErrMalformed},
		{"dh without DigestMethod", cut(legacy, `<ds:DigestMethod`, `</ds:DigestMethod>`), k, both, xmlsec.ErrMalformed},
		{"dh SHA-1 not named", edit(legacy, `Algorithm="`+xmlsec.DigestSHA256+`"`, `Algorithm="`+xmlsec.DigestSHA1+`"`), k, both, xmlsec.ErrAlgorithmNotAllowed},
		{"dh KA-Nonce not base64", edit(legacy, `<ds:DigestMethod`, `<xenc:KA-Nonce>!!</xenc:KA-Nonce><ds:DigestMethod`), k, both, xmlsec.ErrMalformed},
		{"dh KA-Nonce changes the KEK", edit(legacy, `<ds:DigestMethod`, `<xenc:KA-Nonce>Zm9v</xenc:KA-Nonce><ds:DigestMethod`), k, both, nil},
		{"private key in a small group", es, &xenc.DHPrivateKey{DHPublicKey: xenc.DHPublicKey{P: new(big.Int).Rsh(k.P, 1024), Q: k.Q, G: k.G}, X: k.X}, both, xmlsec.ErrUnsupportedKeyInfo},
		{"private X of Q", es, &badX, both, xmlsec.ErrUnsupportedKeyInfo},
		{"private X missing", es, &xenc.DHPrivateKey{DHPublicKey: k.DHPublicKey}, both, xmlsec.ErrUnsupportedKeyInfo},
		{"no KeyValue", cut(es, `<ds:KeyValue><xenc:DHKeyValue><xenc:P>`, `</ds:KeyValue>`), k, both, xmlsec.ErrMalformed},
		{"not a DHKeyValue", edit(edit(es, `<xenc:DHKeyValue>`, `<xenc:Other>`), `</xenc:DHKeyValue>`, `</xenc:Other>`), k, both, xmlsec.ErrMalformed},
		{"foreign child", oki(es, `<ds:P>AA==</ds:P>`), k, both, xmlsec.ErrMalformed},
		{"not base64", oki(es, `<xenc:Public>!!</xenc:Public>`), k, both, xmlsec.ErrMalformed},
		{"Generator before Q", oki(es, el("P", k.P)+el("Generator", k.G)+el("Q", k.Q)+el("Public", k.Y)), k, both, xmlsec.ErrMalformed},
		{"no Public", oki(es, el("P", k.P)+el("Q", k.Q)+el("Generator", k.G)), k, both, xmlsec.ErrMalformed},
		{"1024-bit group", oki(es, el("P", new(big.Int).Rsh(k.P, 1024))+el("Q", k.Q)+el("Generator", k.G)+el("Public", k.Y)), k, both, xmlsec.ErrUnsupportedKeyInfo},
		{"another group", oki(es, el("P", other.P)+el("Q", other.Q)+el("Generator", other.G)+el("Public", other.Y)), k, both, xmlsec.ErrUnsupportedKeyInfo},
		{"another generator", oki(es, el("P", k.P)+el("Q", k.Q)+el("Generator", big.NewInt(4))+el("Public", k.Y)), k, both, xmlsec.ErrUnsupportedKeyInfo},
		{"Public 0", oki(es, `<xenc:Public></xenc:Public>`), k, both, xmlsec.ErrMalformed},
		{"Public 1", oki(es, el("Public", big.NewInt(1))), k, both, xmlsec.ErrMalformed},
		{"Public P-1", oki(es, el("Public", pm1)), k, both, xmlsec.ErrMalformed},
		{"Public P", oki(es, el("Public", k.P)), k, both, xmlsec.ErrMalformed},
		{"Public outside the subgroup", oki(es, el("Public", nonResidue(t, k.P))), k, both, xmlsec.ErrMalformed},
		{"digest outside allow-list", es, k, withDigest(both, xmlsec.DigestSHA512), xmlsec.ErrAlgorithmNotAllowed},
		{"another recipient", es, dhKey(t, ffdhe2048), both, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := xenc.DecryptAgreedKeyDH(covParse(t, c.el), c.priv, c.opts)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if key != nil {
				t.Fatal("key returned with an error")
			}
		})
	}

	// SHA-1 in the Legacy KDF, when named, passes the allow-list and
	// derives another KEK than the SHA-256 the key was wrapped under.
	sha1 := edit(legacy, `Algorithm="`+xmlsec.DigestSHA256+`"`, `Algorithm="`+xmlsec.DigestSHA1+`"`)
	if _, err := xenc.DecryptAgreedKeyDH(covParse(t, sha1), k, withDigest(both, xmlsec.DigestSHA1)); err == nil || errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
		t.Fatalf("SHA-1 named: %v", err)
	}
}

// A DHKeyValue with only Public, and one with seed and pgenCounter, both
// decrypt when the Public is the real originator's.
func TestDHKeyValueForms(t *testing.T) {
	k := dhKey(t, ffdhe2048)
	ek, err := xenc.GenerateEncryptedKey(dhOpts(k, xmlsec.KeyAgreementDHES, xmlsec.KeyWrapAES128, xmlsec.DigestSHA256))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c14n.Bytes(ek.Element, c14n.Options{Algorithm: c14n.Exclusive10})
	s := string(b)
	const open = `<xenc:OriginatorKeyInfo><ds:KeyValue><xenc:DHKeyValue>`
	i := strings.Index(s, open) + len(open)
	j := strings.Index(s, `<xenc:Public>`)
	for name, doc := range map[string]string{
		"Public only":          s[:i] + s[j:],
		"seed and pgenCounter": strings.Replace(s, `</xenc:Public></xenc:DHKeyValue></ds:KeyValue></xenc:OriginatorKeyInfo>`, `</xenc:Public><xenc:seed>AQ==</xenc:seed><xenc:pgenCounter>AQ==</xenc:pgenCounter></xenc:DHKeyValue></ds:KeyValue></xenc:OriginatorKeyInfo>`, 1),
		"KeyName beside":       strings.Replace(s, `<xenc:OriginatorKeyInfo>`, `<xenc:OriginatorKeyInfo><ds:KeyName>o</ds:KeyName>`, 1),
		"KA-Nonce ignored":     strings.Replace(s, `<xenc11:KeyDerivationMethod`, `<xenc:KA-Nonce>Zm9v</xenc:KA-Nonce><xenc11:KeyDerivationMethod`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := xenc.DecryptAgreedKeyDH(covParse(t, doc), k, dhAllow(xmlsec.KeyAgreementDHES))
			if err != nil || !bytes.Equal(key, ek.SessionKey) {
				t.Fatalf("%v\n%s", err, doc)
			}
		})
	}
}

// Section 5.6: finite-field Diffie-Hellman directly in the EncryptedData's
// KeyInfo, with ConcatKDF and with the Legacy KDF, which names the data
// algorithm.
func TestDirectKeyAgreementDH(t *testing.T) {
	k := dhKey(t, ffdhe2048)
	for _, agreement := range []string{xmlsec.KeyAgreementDHES, xmlsec.KeyAgreementDH} {
		t.Run(agreement, func(t *testing.T) {
			opts := dhOpts(k, agreement, "", xmlsec.DigestSHA256)
			opts.DirectKeyAgreement = true
			ed := dkEncrypt(t, opts)
			if _, err := xenc.DecryptAgreedDataKeyDH(ed, k, xenc.DecryptOptions{}); !errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) {
				t.Fatalf("not named: %v", err)
			}
			key, err := xenc.DecryptAgreedDataKeyDH(ed, k, dhAllow(agreement))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
