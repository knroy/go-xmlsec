package xenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/idref"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"golang.org/x/text/unicode/norm"
)

// gcm returns the AEAD for alg, checking the key length against it.
func gcm(alg string, key []byte) (cipher.AEAD, error) {
	size, ok := keySizes[alg]
	if !ok {
		return nil, unsupported("data %q", alg)
	}
	// NewCipher refuses any length AES does not have; the size check then
	// refuses a valid AES key of the wrong size for alg.
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(key) != size {
		return nil, fmt.Errorf("xenc: session key is %d bytes, %s needs %d", len(key), alg, size)
	}
	return cipher.NewGCM(b)
}

// seal returns IV || ciphertext || tag, the XML Encryption 1.1 AES-GCM
// layout, with a fresh 96-bit IV.
func seal(alg string, key, plaintext []byte) ([]byte, error) {
	if err := encryptable(alg); err != nil {
		return nil, err
	}
	a, err := gcm(alg, key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, a.NonceSize())
	rand.Read(iv)
	return a.Seal(iv, iv, plaintext, nil), nil
}

// open decrypts with an algorithm dataAlgorithm has already checked. Every
// failure is the same error: the key usually comes from an unwrap, and its
// length or validity must not be observable.
func open(alg string, key, data []byte) ([]byte, error) {
	if _, ok := cbcSizes[alg]; ok {
		return cbcOpen(alg, key, data)
	}
	a, err := gcm(alg, key)
	if err != nil {
		return nil, errDecrypt
	}
	if len(data) < a.NonceSize()+a.Overhead() {
		return nil, malformed("AES-GCM ciphertext too short")
	}
	pt, err := a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], nil)
	if err != nil {
		return nil, errDecrypt
	}
	return pt, nil
}

// defaultNS returns the default namespace in scope at n, "" for none.
func defaultNS(n *xdm.Node) string {
	uri, _ := n.LookupPrefix("")
	return uri
}

// elementPlaintext serializes e for an EncryptedData that will replace it
// or its parent's content, parent being the element whose default
// namespace the decrypted octets are parsed under (section 4.5.1).
//
// The octets are e's inclusive canonical form, which declares every
// namespace in scope, so they also parse on their own. Canonical form
// suppresses xmlns="" on the apex, so when e has no default namespace and
// parent has one, xmlns="" is added (section 4.5.3.1): a peer that decrypts
// and replaces would otherwise put e in parent's namespace.
func elementPlaintext(e, parent *xdm.Node) ([]byte, error) {
	b, err := c14n.Bytes(e, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if err != nil {
		return nil, err
	}
	if defaultNS(e) == "" && defaultNS(parent) != "" {
		b = slices.Insert(b, bytes.IndexAny(b, " >"), []byte(` xmlns=""`)...)
	}
	return b, nil
}

// nfc refuses plaintext outside Normalization Form C (section 4.3).
func nfc(b []byte) error {
	if !norm.NFC.IsNormal(b) {
		return xmlsec.ErrNotNFC
	}
	return nil
}

// checkTarget refuses a target that is not an element inside doc.
func checkTarget(doc, target *xdm.Node) error {
	if doc == nil || target == nil || target.Kind != xdm.KindElement || target.Parent == nil || target.Root() != doc.Root() {
		return errors.New("xenc: target must be an element inside doc")
	}
	return nil
}

// isSOAP reports whether e is the SOAP 1.1 or 1.2 element named local.
func isSOAP(e *xdm.Node, local string) bool {
	return e.IsElement(xmlsec.NSSOAP11, local) || e.IsElement(xmlsec.NSSOAP12, local)
}

// encryptedData encrypts plaintext into an xenc:EncryptedData of Type typ.
func encryptedData(typ string, plaintext, sessionKey []byte, opts EncryptOptions) (*xdm.Node, error) {
	ed, err := newEncryptedData(typ, opts)
	if err != nil {
		return nil, err
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, plaintext)
	if err != nil {
		return nil, err
	}
	cd := element(ed, "CipherData")
	place(ed)
	xmltree.Text(element(cd, "CipherValue"), base64.StdEncoding.EncodeToString(ct))
	return ed, nil
}

// emitWith returns the canonical octets of doc with parent's children
// replaced by kids, which include the new nodes added, and restores parent.
func emitWith(doc, parent *xdm.Node, kids []*xdm.Node, added ...*xdm.Node) ([]byte, error) {
	saved := parent.Children
	for _, n := range added {
		parent.AppendChild(n)
	}
	parent.Children = kids
	defer func() { parent.Children = saved }()
	return c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
}

// replaceElement encrypts target and emits doc with wrap(EncryptedData) in
// target's place.
func replaceElement(doc, target *xdm.Node, sessionKey []byte, opts EncryptOptions, wrap func(*xdm.Node) (*xdm.Node, error)) ([]byte, error) {
	plain, err := elementPlaintext(target, target.Parent)
	if err != nil {
		return nil, err
	}
	if err := nfc(plain); err != nil {
		return nil, err
	}
	ed, err := encryptedData(TypeElement, plain, sessionKey, opts)
	if err != nil {
		return nil, err
	}
	repl, err := wrap(ed)
	if err != nil {
		return nil, err
	}
	kids := slices.Clone(target.Parent.Children)
	kids[slices.Index(kids, target)] = repl
	return emitWith(doc, target.Parent, kids, repl)
}

// EncryptElement replaces target with an xenc:EncryptedData of Type
// Element holding its encrypted form, and returns the resulting document
// octets. doc itself is left unmodified.
//
// The plaintext is target's inclusive canonical form, which declares every
// namespace in scope on the element, so the decrypted octets parse on their
// own, plus xmlns="" on target when it has no default namespace and its
// parent has one (section 4.5.3.1). It must be in Unicode Normalization
// Form C (section 4.3), or xmlsec.ErrNotNFC is returned. The returned document is
// in canonical form (Inclusive10WithComments).
//
// A SOAP Envelope, Header or Body, and a header block, a direct child of a
// SOAP Header, are refused: WS-Security forbids encrypting the first three
// and requires a header block to become a wsse11:EncryptedHeader (WS-I BSP
// R3228, R5614); use EncryptHeader for that.
func EncryptElement(doc *xdm.Node, target *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	if err := checkTarget(doc, target); err != nil {
		return nil, err
	}
	switch {
	case isSOAP(target, "Envelope") || isSOAP(target, "Header") || isSOAP(target, "Body"):
		return nil, fmt.Errorf("xenc: a SOAP %s must not be encrypted", target.Name.Local)
	case isSOAP(target.Parent, "Header"):
		return nil, errors.New("xenc: a SOAP header block must be encrypted with EncryptHeader")
	}
	return replaceElement(doc, target, sessionKey, opts, func(ed *xdm.Node) (*xdm.Node, error) { return ed, nil })
}

// EncryptContent replaces the content of target (its child nodes, not its
// attributes) with an xenc:EncryptedData of Type Content, and returns the
// resulting document octets. doc itself is left unmodified.
//
// The plaintext is each child in turn: a child element as EncryptElement
// serializes it, with target as the context whose default namespace it is
// parsed under, and text, comments and processing instructions in canonical
// form. It must be in Normalization Form C.
//
// The content of a SOAP Envelope or Header is refused: the EncryptedData
// would leave the envelope invalid (WS-I BSP R5607, R3228). The content of
// a SOAP Body is what WS-Security usually encrypts.
//
// DecryptData returns the content's octets. To restore them, parse them as
// the content of an element declaring the namespaces in scope at target,
// and put the resulting nodes in place of the EncryptedData.
func EncryptContent(doc *xdm.Node, target *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	if err := checkTarget(doc, target); err != nil {
		return nil, err
	}
	if isSOAP(target, "Envelope") || isSOAP(target, "Header") {
		return nil, fmt.Errorf("xenc: the content of a SOAP %s must not be encrypted", target.Name.Local)
	}
	var plain []byte
	for _, c := range target.Children {
		var b []byte
		var err error
		if c.Kind == xdm.KindElement {
			b, err = elementPlaintext(c, target)
		} else {
			b, err = c14n.BytesNodeSet(c14n.Func(c, func(n *xdm.Node) bool { return n == c }),
				c14n.Options{Algorithm: c14n.Inclusive10WithComments})
		}
		if err != nil {
			return nil, err
		}
		plain = append(plain, b...)
	}
	if err := nfc(plain); err != nil {
		return nil, err
	}
	ed, err := encryptedData(TypeContent, plain, sessionKey, opts)
	if err != nil {
		return nil, err
	}
	return emitWith(doc, target, []*xdm.Node{ed}, ed)
}

// DecryptData decrypts an xenc:EncryptedData whose ciphertext is inline in
// xenc:CipherValue, or held in the same document and named by an
// xenc:CipherReference: URI="#id" for the element with that Id, wsu:Id or
// xml:id (refused if more than one carries it), or URI="" for the whole
// document, with exactly the base64 transform, which decodes the text
// content. With opts.ResolveURI set, a CipherReference to an absolute URI
// other than cid: is fetched through it (section 3.3.1): its octets are the
// ciphertext, or, with exactly the base64 transform, its base64 encoding.
// A relative URI is first resolved against opts.BaseURI, and refused
// without one. Any other CipherReference is refused; attachments are
// DecryptAttachment's.
//
// With opts.AllowedXPathExpressions, an XPath transform the list allows may
// precede the base64 transform (Example 13). The text nodes for which the
// expression is true, among those of the named element, of the whole
// document, or of the resolved octets parsed with xmlsec.Parse, are
// concatenated in document order and decoded as the ciphertext. The
// expression is checked before ResolveURI is called.
//
// For an encrypted element the result is the element's octets, and for
// Type Content the content's (see EncryptContent); DecryptAndReplace puts
// them in place of the EncryptedData.
//
// opts.AllowedDataAlgorithms restricts the data algorithm; empty means the
// default set, AES-GCM. The legacy CBC algorithms (xmlsec.EncAES128CBC, EncAES192CBC,
// EncAES256CBC, EncTripleDESCBC) are decrypted only when named: the IV is
// the first block, and of the section 5.2.1 padding only the last octet is
// checked. Every CBC failure (wrong key, bad length, bad padding) is the
// same error, judged after the whole ciphertext is decrypted. That does not
// stop the padding-oracle attack of section 6.1.1: CBC is not
// authenticated, and an attacker who can submit altered ciphertext learns
// from anything that differs afterwards, such as whether the plaintext
// parses. Only authentication bound to the key closes it: AES-GCM.
func DecryptData(el *xdm.Node, sessionKey []byte, opts DecryptOptions) ([]byte, error) {
	alg, err := dataAlgorithm(el, opts.AllowedDataAlgorithms)
	if err != nil {
		return nil, err
	}
	ct, err := dataCiphertext(el, opts)
	if err != nil {
		return nil, err
	}
	return open(alg, sessionKey, ct)
}

// dataCiphertext returns the ciphertext of an EncryptedData, inline, by
// same-document CipherReference, or by external CipherReference through
// opts.ResolveURI.
func dataCiphertext(el *xdm.Node, opts DecryptOptions) ([]byte, error) {
	cd, err := cipherData(el)
	if err != nil {
		return nil, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSXEnc, "CipherReference") {
		return cipherValue(el)
	}
	cr := kids[0]
	uri := cr.AttrValue("URI")
	ext, err := externalURI(uri, opts)
	if err != nil {
		return nil, err
	}
	algs, xp, err := cipherTransforms(cr, opts.AllowedXPathExpressions)
	if err != nil {
		return nil, err
	}
	if ext != "" {
		return externalCiphertext(ext, algs, xp, opts.ResolveURI)
	}
	if !slices.Equal(algs, []string{xmlsec.TransformBase64}) && !slices.Equal(algs, xpathBase64) {
		return nil, unsupported("same-document CipherReference transforms %q: the base64 transform, optionally after an allowed XPath, is supported", algs)
	}
	src := el.Root()
	if uri != "" {
		if src, err = idref.Find(el, uri[1:], idAttr); err != nil {
			return nil, err
		}
	}
	if xp != nil {
		return xp.decode(src)
	}
	b, err := xmltree.Base64(src)
	if err != nil {
		return nil, malformed("CipherReference content: %v", err)
	}
	return b, nil
}

// externalCiphertext fetches the octets of an external CipherReference
// through resolve, once its transforms are accepted: none, for the
// ciphertext itself, base64, for its encoding, or an allowed XPath and then
// base64, for an encoding held in the text of an XML document.
func externalCiphertext(uri string, algs []string, xp *xpathStep, resolve xmlsec.URIResolver) ([]byte, error) {
	if len(algs) > 1 && !slices.Equal(algs, xpathBase64) || len(algs) == 1 && algs[0] != xmlsec.TransformBase64 {
		return nil, unsupported("external CipherReference transforms %q: none, base64, or an allowed XPath then base64 is supported", algs)
	}
	b, err := resolve(uri)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", xmlsec.ErrDereference, uri, err)
	}
	switch {
	case len(algs) == 0:
		return b, nil
	case xp != nil:
		tree, err := xmlsec.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%w: CipherReference content for XPath: %w", xmlsec.ErrMalformed, err)
		}
		return xp.decode(tree.Root)
	}
	return decode64(string(b))
}

// decode64 decodes base64 text, ignoring whitespace.
func decode64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, malformed("CipherReference content: %v", err)
	}
	return b, nil
}

// dataAlgorithm validates el as xenc:EncryptedData and returns its allowed,
// implemented data algorithm, whose xenc:EncryptionMethod may hold only a
// consistent KeySize.
func dataAlgorithm(el *xdm.Node, allowedData []string) (string, error) {
	if el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedData") {
		return "", malformed("not an xenc:EncryptedData")
	}
	alg, m, err := parseEncryptionMethod(el)
	if err != nil {
		return "", err
	}
	if err := allowed("data", alg, allowedData, defaultData); err != nil {
		return "", err
	}
	size, ok := dataKeySize(alg)
	if !ok {
		return "", unsupported("data %q", alg)
	}
	if _, err := methodParams(m, size*8); err != nil {
		return "", err
	}
	return alg, nil
}
