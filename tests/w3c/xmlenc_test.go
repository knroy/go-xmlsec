package w3c

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
// xenc:EncryptedKey. key names the recipient's EC key; want is nil for a
// vector that must decrypt to plaintext.xml, or the refusal expected.
var xmlencVectors = []struct {
	file, key string
	want      error
	reason    string
}{
	{"cipherText__EC-P256__aes128-gcm__kw-aes128__ECDH-ES__ConcatKDF.xml", "EC-P256", nil, ""},
	{"cipherText__EC-P384__aes192-gcm__kw-aes192__ECDH-ES__ConcatKDF.xml", "EC-P384", nil, ""},
	{"cipherText__EC-P521__aes256-gcm__kw-aes256__ECDH-ES__ConcatKDF.xml", "EC-P521", nil, ""},
	{"cipherText__EC-P256__aes128-gcm__kw-aes256__ECDH-ES__pbkdf2.xml", "EC-P256", xmlsec.ErrUnsupportedAlgorithm, "PBKDF2 key derivation is not implemented"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__ConcatKDF.xml", "EC-P256", xmlsec.ErrAlgorithmNotAllowed, "finite-field dh-es is not in the default set"},
	{"cipherText__DH-1024__aes128-gcm__kw-aes128__dh-es__pbkdf2.xml", "EC-P256", xmlsec.ErrAlgorithmNotAllowed, "finite-field dh-es is not in the default set"},
	{"cipherText__RSA-2048__aes128-gcm__rsa-oaep-mgf1p.xml", "", xmlsec.ErrAlgorithmNotAllowed, "rsa-oaep-mgf1p implies SHA-1 MGF"},
	{"cipherText__RSA-3072__aes192-gcm__rsa-oaep-mgf1p__Sha256.xml", "", xmlsec.ErrAlgorithmNotAllowed, "rsa-oaep-mgf1p implies SHA-1 MGF"},
	{"cipherText__RSA-3072__aes256-gcm__rsa-oaep__Sha384-MGF_Sha1.xml", "", xmlsec.ErrAlgorithmNotAllowed, "SHA-1 MGF"},
	{"cipherText__RSA-4096__aes256-gcm__rsa-oaep__Sha512-MGF_Sha1_PSource.xml", "", xmlsec.ErrAlgorithmNotAllowed, "SHA-1 MGF"},
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
		if found == nil && e.IsElement(xenc.NSXEnc, local) {
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
			if v.key == "" {
				key, err = xenc.DecryptEncryptedKey(ek, rsaKey, nil, nil, nil)
			} else {
				key, err = xenc.DecryptAgreedKey(ek, ecKey(t, v.key), nil, nil, nil)
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
			got, err := xenc.DecryptData(ed, key, nil)
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
