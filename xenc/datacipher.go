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

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/idref"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
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

// The AES-GCM IV and tag lengths cipher.NewGCM uses.
const (
	ivSize  = 12
	tagSize = 16
)

// seal encrypts buf[ivSize:] in place, with a fresh 96-bit IV written to
// buf[:ivSize], and returns IV || ciphertext || tag, the XML Encryption 1.1
// AES-GCM layout. buf is reused when it has room for the tag.
func seal(alg string, key, buf []byte) ([]byte, error) {
	if err := encryptable(alg); err != nil {
		return nil, err
	}
	a, err := gcm(alg, key)
	if err != nil {
		return nil, err
	}
	iv := buf[:ivSize]
	rand.Read(iv)
	return a.Seal(iv, iv, buf[ivSize:], nil), nil
}

// sealBuf returns a buffer for seal holding a copy of plaintext, which
// belongs to the caller.
func sealBuf(plaintext []byte) []byte {
	return append(make([]byte, ivSize, ivSize+len(plaintext)+tagSize), plaintext...)
}

// ownSealBuf returns plaintext, which this package owns, moved up by the
// IV: the buffer for seal, in plaintext's own storage when it has room.
func ownSealBuf(plaintext []byte) []byte {
	n := len(plaintext)
	b := slices.Grow(plaintext, ivSize+tagSize)[:ivSize+n]
	copy(b[ivSize:], b[:n])
	return b
}

// base64Text returns the base64 encoding of b, encoded straight into the
// string.
func base64Text(b []byte) string {
	var s strings.Builder
	s.Grow(base64.StdEncoding.EncodedLen(len(b)))
	w := base64.NewEncoder(base64.StdEncoding, &s)
	// A strings.Builder never fails a write, so neither can the encoder.
	_, _ = w.Write(b)
	_ = w.Close()
	return s.String()
}

// open decrypts with an algorithm dataAlgorithm has already checked. Every
// failure is the same error: the key usually comes from an unwrap, and its
// length or validity must not be observable. With own, data is this
// package's and is decrypted in place; otherwise it is the caller's and is
// left as it was.
func open(alg string, key, data []byte, own bool) ([]byte, error) {
	if _, ok := cbcSizes[alg]; ok {
		return cbcOpen(alg, key, data, own)
	}
	a, err := gcm(alg, key)
	if err != nil {
		return nil, errDecrypt
	}
	if len(data) < a.NonceSize()+a.Overhead() {
		return nil, malformed("AES-GCM ciphertext too short")
	}
	var dst []byte
	if own {
		dst = data[a.NonceSize():a.NonceSize()]
	}
	pt, err := a.Open(dst, data[:a.NonceSize()], data[a.NonceSize():], nil)
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
	if doc == nil || target == nil || target.Kind() != xdm.KindElement || target.Parent() == nil || target.Root() != doc.Root() {
		return errors.New("xenc: target must be an element inside doc")
	}
	return nil
}

// isSOAP reports whether e is the SOAP 1.1 or 1.2 element named local.
func isSOAP(e *xdm.Node, local string) bool {
	return e.IsElement(xmlsec.NSSOAP11, local) || e.IsElement(xmlsec.NSSOAP12, local)
}

// encryptedData encrypts plaintext, which this package owns and overwrites,
// into an xenc:EncryptedData of Type typ.
func encryptedData(typ string, plaintext, sessionKey []byte, opts EncryptOptions) (*xdm.Node, error) {
	ed, err := newEncryptedData(typ, "", opts)
	if err != nil {
		return nil, err
	}
	if sessionKey, err = dataKey(ed, sessionKey, opts); err != nil {
		return nil, err
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, ownSealBuf(plaintext))
	if err != nil {
		return nil, err
	}
	xmltree.Text(element(element(ed, "CipherData"), "CipherValue"), base64Text(ct))
	if err := addProperties(ed, opts); err != nil {
		return nil, err
	}
	return ed, nil
}

// emit returns the canonical octets of a copy of doc with e applied. doc
// itself is left as it was.
func emit(doc *xdm.Node, e *xmltree.Edits) ([]byte, error) {
	return c14n.Bytes(xmltree.RebuildTree(doc, e), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
}

// replaceElement encrypts target and emits doc with wrap(EncryptedData) in
// target's place.
func replaceElement(doc, target *xdm.Node, sessionKey []byte, opts EncryptOptions, wrap func(*xdm.Node) (*xdm.Node, error)) ([]byte, error) {
	plain, err := elementPlaintext(target, target.Parent())
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
	var e xmltree.Edits
	e.ReplaceNode(target, repl)
	return emit(doc, &e)
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
		return nil, fmt.Errorf("xenc: a SOAP %s must not be encrypted", target.Name().Local)
	case isSOAP(target.Parent(), "Header"):
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
// DecryptData returns the content's octets, and DecryptAndReplace puts
// them back in place of the EncryptedData.
func EncryptContent(doc *xdm.Node, target *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	if err := checkTarget(doc, target); err != nil {
		return nil, err
	}
	if isSOAP(target, "Envelope") || isSOAP(target, "Header") {
		return nil, fmt.Errorf("xenc: the content of a SOAP %s must not be encrypted", target.Name().Local)
	}
	var parts [][]byte
	for c := range target.Children() {
		var b []byte
		var err error
		if c.Kind() == xdm.KindElement {
			b, err = elementPlaintext(c, target)
		} else {
			b, err = c14n.BytesNodeSet(c14n.Func(c, func(n *xdm.Node) bool { return n == c }),
				c14n.Options{Algorithm: c14n.Inclusive10WithComments})
		}
		if err != nil {
			return nil, err
		}
		parts = append(parts, b)
	}
	plain := join(parts)
	if err := nfc(plain); err != nil {
		return nil, err
	}
	ed, err := encryptedData(TypeContent, plain, sessionKey, opts)
	if err != nil {
		return nil, err
	}
	var e xmltree.Edits
	first := true
	for c := range target.Children() {
		if first {
			e.ReplaceNode(c, ed)
		} else {
			e.ReplaceNode(c)
		}
		first = false
	}
	if first {
		e.Insert(target, 0, ed)
	}
	return emit(doc, &e)
}

// join concatenates parts, which this package owns, in the storage of the
// largest when that has room for the rest, the IV and the tag, as the
// slack c14n.Bytes leaves usually does for the whitespace around an
// element: content costs one buffer however its children split.
func join(parts [][]byte) []byte {
	if len(parts) == 0 {
		return nil
	}
	k, before, total := 0, 0, 0
	for i, p := range parts {
		if len(p) > len(parts[k]) {
			k, before = i, total
		}
		total += len(p)
	}
	n := len(parts[k])
	out := slices.Grow(parts[k], total-n+ivSize+tagSize)[:total]
	copy(out[before:], out[:n])
	at := 0
	for i, p := range parts {
		if i != k {
			copy(out[at:], p)
		}
		at += len(p)
	}
	return out
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
	if err := strictData(el, opts); err != nil {
		return nil, err
	}
	alg, err := dataAlgorithm(el, opts)
	if err != nil {
		return nil, err
	}
	ct, own, err := dataCiphertext(el, opts)
	if err != nil {
		return nil, err
	}
	return open(alg, sessionKey, ct, own)
}

// dataCiphertext returns the ciphertext of an EncryptedData, inline, by
// same-document CipherReference, or by external CipherReference through
// opts.ResolveURI. own reports that the ciphertext is this package's to
// decrypt in place: everything but the octets ResolveURI returned, which
// are the caller's.
func dataCiphertext(el *xdm.Node, opts DecryptOptions) (ct []byte, own bool, err error) {
	cd, err := cipherData(el)
	if err != nil {
		return nil, false, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSXEnc, "CipherReference") {
		ct, err = cipherValue(cd)
		return ct, true, err
	}
	cr := kids[0]
	// The schema requires URI (section 3.3.1); only a present URI="" means
	// the whole document.
	if cr.Attr("", "URI") == nil {
		return nil, false, malformed("xenc:CipherReference without a URI attribute")
	}
	uri := cr.AttrValue("URI")
	ext, err := externalURI(uri, opts)
	if err != nil {
		return nil, false, err
	}
	algs, xp, err := cipherTransforms(cr, opts.AllowedXPathExpressions)
	if err != nil {
		return nil, false, err
	}
	if ext != "" {
		ct, err = externalCiphertext(ext, algs, xp, opts.ResolveURI)
		return ct, len(algs) != 0, err
	}
	if !slices.Equal(algs, []string{xmlsec.TransformBase64}) && !slices.Equal(algs, xpathBase64) {
		return nil, false, unsupported("same-document CipherReference transforms %q: the base64 transform, optionally after an allowed XPath, is supported", algs)
	}
	src := el.Root()
	if uri != "" {
		if src, err = idref.Find(el, uri[1:], idAttr); err != nil {
			return nil, false, err
		}
	}
	if xp != nil {
		ct, err = xp.decode(src)
		return ct, true, err
	}
	b, err := xmltree.Base64(src)
	if err != nil {
		return nil, false, malformed("CipherReference content: %v", err)
	}
	return b, true, nil
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
// consistent KeySize, or opts.ImpliedDataAlgorithm when it has none.
func dataAlgorithm(el *xdm.Node, opts DecryptOptions) (string, error) {
	if el == nil || !el.IsElement(xmlsec.NSXEnc, "EncryptedData") {
		return "", malformed("not an xenc:EncryptedData")
	}
	alg, m, err := parseEncryptionMethod(el, opts.ImpliedDataAlgorithm)
	if err != nil {
		return "", err
	}
	if err := allowed("data", alg, opts.AllowedDataAlgorithms, defaultData); err != nil {
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
