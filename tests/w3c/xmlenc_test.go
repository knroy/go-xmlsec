package w3c

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/xenc"
)

// The XML Encryption 1.1 interop vectors (Oracle, 2012), each an
// xenc:EncryptedData of plaintext.xml whose ds:KeyInfo holds the
// xenc:EncryptedKey. key names the recipient's EC key, or "DH" for a
// finite-field one; opts are the allow-lists; want is nil for a vector
// that must decrypt to plaintext.xml, or the refusal expected.
var xmlencVectors = []struct {
	file, key string
	opts      xenc.DecryptOptions
	want      error
	reason    string
}{
	{"cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.xml", "EC-P256", xenc.DecryptOptions{}, nil, ""},
	{"cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.xml", "EC-P384", xenc.DecryptOptions{}, nil, ""},
	{"cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.xml", "EC-P521", xenc.DecryptOptions{}, nil, ""},
	{"cipherText__EC-P256__aes128-gcm__kw-aes256__ECDH-ES__pbkdf2.xml", "EC-P256", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "PBKDF2 is not in the default set"},
	{"cipherText__EC-P256__aes128-gcm__kw-aes256__ECDH-ES__pbkdf2.xml", "EC-P256", pbkdf2, errNotReproduced, "no encoding of the shared secret as the PBKDF2 password tried reproduces the KEK; xmlsec1's suite leaves this vector out, and the reading implemented, the secret's octets, matches xmlsec1 (tests/interop)"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF.xml", "DH", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "finite-field dh-es is not in the default set"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF.xml", "DH", dhES, xmlsec.ErrUnsupportedKeyInfo, "a 1024-bit group, under the 2048-bit floor"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__pbkdf2.xml", "DH", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "finite-field dh-es is not in the default set"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__pbkdf2.xml", "DH", dhES, xmlsec.ErrUnsupportedKeyInfo, "a 1024-bit group, under the 2048-bit floor"},
	{"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml", "", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "rsa-oaep-mgf1p implies SHA-1 MGF"},
	{"cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml", "", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "rsa-oaep-mgf1p implies SHA-1 MGF"},
	{"cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml", "", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "SHA-1 MGF"},
	{"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml", "", xenc.DecryptOptions{}, xmlsec.ErrAlgorithmNotAllowed, "SHA-1 MGF"},
}

// errNotReproduced marks a vector whose key unwrap fails: it is parsed and
// accepted, but the KEK it was wrapped under cannot be derived.
var errNotReproduced = errors.New("KEK not reproduced")

var (
	pbkdf2 = xenc.DecryptOptions{AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2}}
	dhES   = xenc.DecryptOptions{
		AllowedKeyAgreementAlgorithms:  []string{xmlsec.KeyAgreementDHES},
		AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationConcatKDF, xmlsec.KeyDerivationPBKDF2},
	}
)

// dhKey is a key in the RFC 7919 ffdhe2048 group. The DH-1024 vectors'
// own key is not needed: their 1024-bit group is refused before any
// exponentiation, whatever the recipient's key.
func dhKey(t *testing.T) *xenc.DHPrivateKey {
	t.Helper()
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
	k, err := xenc.GenerateDHKey(p, new(big.Int).Rsh(p, 1), big.NewInt(2))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecKey(t *testing.T, name string) *ecdh.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "xmlenc11", name+"_SHA256WithECDSA.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := k.(*ecdsa.PrivateKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func find(n *xdm.Node, local string) *xdm.Node {
	var found *xdm.Node
	xmltree.Walk(n, func(e *xdm.Node) {
		if found == nil && e.IsElement(xmlsec.NSXEnc, local) {
			found = e
		}
	})
	return found
}

func TestW3CXMLEncryptionVectors(t *testing.T) {
	plain, err := os.ReadFile(filepath.Join("testdata", "xmlenc11", "plaintext.xml"))
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range xmlencVectors {
		t.Run(v.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "xmlenc11", v.file))
			if err != nil {
				t.Fatal(err)
			}
			tree, err := xmlsec.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			ed := find(tree.Root, "EncryptedData")
			ek, err := xenc.FindEncryptedKey(ed)
			if err != nil {
				t.Fatal(err)
			}
			var key []byte
			switch v.key {
			case "":
				key, err = xenc.DecryptEncryptedKey(ek, rsaKey, v.opts)
			case "DH":
				key, err = xenc.DecryptAgreedKeyDH(ek, dhKey(t), v.opts)
			default:
				key, err = xenc.DecryptAgreedKey(ek, ecKey(t, v.key), v.opts)
			}
			if v.want == errNotReproduced {
				if err == nil || errors.Is(err, xmlsec.ErrAlgorithmNotAllowed) || errors.Is(err, xmlsec.ErrMalformed) {
					t.Fatalf("got %v, want a failed unwrap (%s)", err, v.reason)
				}
				return
			}
			if v.want != nil {
				if !errors.Is(err, v.want) {
					t.Fatalf("got %v, want %v (%s)", err, v.want, v.reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			// The encrypted octets are not byte-identical to plaintext.xml
			// (their serializations differ by nine octets), so the two are
			// compared as canonical XML.
			gotTree, err := xmlsec.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			wantTree, err := xmlsec.Parse(plain)
			if err != nil {
				t.Fatal(err)
			}
			if eq, err := c14n.Equal(gotTree.Root, wantTree.Root, c14n.Options{Algorithm: c14n.Inclusive10}); !eq || err != nil {
				t.Fatalf("plaintext %q, %v\nwant\n%q", got, err, plain)
			}
		})
	}
}
