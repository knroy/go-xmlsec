package xenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// gcm returns the AEAD for alg, checking the key length against it.
func gcm(alg string, key []byte) (cipher.AEAD, error) {
	size, ok := keySizes[alg]
	if !ok {
		return nil, fmt.Errorf("%w: data %q", xmlsec.ErrUnsupportedAlgorithm, alg)
	}
	if len(key) != size {
		return nil, fmt.Errorf("xenc: session key is %d bytes, %s needs %d", len(key), alg, size)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// seal returns IV || ciphertext || tag, the XML Encryption 1.1 AES-GCM
// layout, with a fresh 96-bit IV.
func seal(alg string, key, plaintext []byte) ([]byte, error) {
	a, err := gcm(alg, key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, a.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return a.Seal(iv, iv, plaintext, nil), nil
}

func open(alg string, key, data []byte) ([]byte, error) {
	a, err := gcm(alg, key)
	if err != nil {
		return nil, err
	}
	if len(data) < a.NonceSize()+a.Overhead() {
		return nil, malformed("AES-GCM ciphertext too short")
	}
	pt, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("xenc: decryption failed")
	}
	return pt, nil
}

// EncryptElement replaces target with an xenc:EncryptedData holding its
// encrypted form, and returns the resulting document octets. doc itself is
// left unmodified.
//
// The plaintext is target's inclusive canonical form, which declares every
// namespace in scope on the element, so the decrypted octets parse on their
// own. The returned document is also in canonical form
// (Inclusive10WithComments).
func EncryptElement(doc *xdm.Node, target *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	parent := target.Parent
	if target.Kind != xdm.KindElement || parent == nil || target.Root() != doc.Root() {
		return nil, errors.New("xenc: target must be an element inside doc")
	}
	plain, err := c14n.Bytes(target, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		return nil, err
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, plain)
	if err != nil {
		return nil, err
	}

	ed := newRoot("EncryptedData")
	xmltree.SetAttr(ed, "", "", "Type", TypeElement)
	encryptionMethod(ed, opts.DataAlgorithm)
	xmltree.Text(element(element(ed, "CipherData"), "CipherValue"), base64.StdEncoding.EncodeToString(ct))

	i := indexOf(parent.Children, target)
	parent.AppendChild(ed)
	parent.Children = parent.Children[:len(parent.Children)-1]
	parent.Children[i] = ed
	defer func() { parent.Children[i] = target }()

	return c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
}

func indexOf(s []*xdm.Node, n *xdm.Node) int {
	for i, c := range s {
		if c == n {
			return i
		}
	}
	return -1
}

// DecryptData decrypts an xenc:EncryptedData whose ciphertext is inline in
// xenc:CipherValue. For an encrypted element the result is the element's
// octets; replacing the EncryptedData with them is the caller's step.
func DecryptData(el *xdm.Node, sessionKey []byte, allowedData []string) ([]byte, error) {
	alg, err := dataAlgorithm(el, allowedData)
	if err != nil {
		return nil, err
	}
	ct, err := cipherValue(el)
	if err != nil {
		return nil, err
	}
	return open(alg, sessionKey, ct)
}

// dataAlgorithm validates el as xenc:EncryptedData and returns its allowed
// data algorithm.
func dataAlgorithm(el *xdm.Node, allowedData []string) (string, error) {
	if !el.IsElement(NSXEnc, "EncryptedData") {
		return "", malformed("not an xenc:EncryptedData")
	}
	alg, _, err := parseEncryptionMethod(el)
	if err != nil {
		return "", err
	}
	_, known := keySizes[alg]
	return alg, allowed("data", alg, allowedData, known)
}
