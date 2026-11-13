package dsig

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/swa"
)

// impliesC14N reports whether a reference relies on the implicit Canonical
// XML 1.0 of XML-DSig 4.4.3.2: its data object is a node set after the last
// transform. A same-document dereference (sameDocument) yields a node set;
// canonicalization, base64 and XSLT yield octets; the XPath transforms
// yield a node set again.
func impliesC14N(sameDocument bool, transforms []TransformSpec) bool {
	nodeSet := sameDocument
	for _, t := range transforms {
		switch a := t.Algorithm; {
		case isC14N(a) || a == xmlsec.TransformBase64 || a == xmlsec.TransformXSLT || a == xmlsec.TransformSTR:
			nodeSet = false
		case a == xmlsec.TransformXPath || a == xmlsec.TransformXPathFilter2:
			nodeSet = true
		}
	}
	return nodeSet
}

// isSameDocument reports whether uri is a same-document reference (XML-DSig
// 4.4.3.2): empty, or a fragment.
func isSameDocument(uri string) bool { return uri == "" || strings.HasPrefix(uri, "#") }

// xpointerID matches #xpointer(id('ID')) and #xpointer(id("ID")).
var xpointerID = regexp.MustCompile(`^#xpointer\(id\((?:'([^']*)'|"([^"]*)")\)\)$`)

// sameDocumentTarget reads a same-document URI. whole is true for "" and
// "#xpointer(/)"; otherwise id names an element: the fragment of "#id", or
// the ID of "#xpointer(id('ID'))". comments is true for the two
// scheme-based XPointers, whose node set keeps comments (XML-DSig 4.4.3.3).
// Any other xpointer() expression is refused.
func sameDocumentTarget(uri string) (id string, whole, comments bool, err error) {
	switch {
	case uri == "":
		return "", true, false, nil
	case uri == "#xpointer(/)":
		return "", true, true, nil
	case strings.HasPrefix(uri, "#xpointer("):
		m := xpointerID.FindStringSubmatch(uri)
		if m == nil || !xdm.IsNCName(m[1]+m[2]) {
			return "", false, false, fmt.Errorf("%w: XPointer %q; only #xpointer(/) and #xpointer(id('ID')) are supported", xmlsec.ErrMalformed, uri)
		}
		return m[1] + m[2], false, true, nil
	}
	return uri[1:], false, false, nil
}

// dereferenced is what a reference actually covered, derived while
// digesting it rather than inferred from its URI.
type dereferenced struct {
	element    *xdm.Node          // "#id" or #xpointer(id('ID')) target
	id         string             // the ID that resolved to element
	attachment *xmlsec.Attachment // cid: target
	whole      bool               // "" or #xpointer(/) target
	external   string             // absolute URI the resolver supplied
	token      *xdm.Node          // token the STR Dereference Transform digested
}

// isExternal reports whether uri is absolute, the only kind a URIResolver
// is given: a relative reference is first resolved against the caller's
// BaseURI (absoluteURI), or refused.
func isExternal(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && u.IsAbs()
}

// checkBaseURI admits a SignOptions or VerifyOptions BaseURI: empty, or an
// absolute URI.
func checkBaseURI(base string) error {
	if base == "" || isExternal(base) {
		return nil
	}
	return fmt.Errorf("%w: BaseURI %q is not an absolute URI", xmlsec.ErrMalformed, base)
}

// absoluteURI resolves a relative reference URI against base (XML-DSig
// 4.4.3.1, RFC 3986 section 5) when base is set. A same-document or
// absolute URI is returned as it is, and so is one that does not parse, for
// digestReference to refuse. base is always the caller's, never xml:base
// or anything else from the document; checkBaseURI has admitted it.
func absoluteURI(base, uri string) string {
	if base == "" || isSameDocument(uri) || isExternal(uri) {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	b, _ := url.Parse(base)
	return b.ResolveReference(u).String()
}

// digestReference dereferences uri, applies transforms in order and writes
// the resulting octets into h. sig is the ds:Signature the reference
// belongs to, which the enveloped-signature transform removes; when the
// signature is not yet in the document, that removal is a no-op.
//
// implicit applies XML-DSig 4.4.3.2: a same-document reference whose
// transforms end in a node set is converted to octets with Canonical XML
// 1.0. Verification applies it, because most signers rely on it; signing
// does not, so this library never produces a signature that depends on it.
//
// idAttrs are the ID attributes "#id" resolves against beyond wsu:Id and
// xml:id. resolve supplies the octets of an absolute URI other than cid:;
// when nil, such a reference is refused. deref finds the token of a
// reference through the STR Dereference Transform.
func digestReference(h hash.Hash, doc, sig *xdm.Node, uri string, transforms []TransformSpec,
	atts xmlsec.AttachmentSet, implicit bool, idAttrs []xdm.QName, resolve xmlsec.URIResolver, deref tokenDeref) (dereferenced, error) {

	var (
		out dereferenced
		in  = data{strDeref: deref}
	)
	switch {
	case isSameDocument(uri):
		id, whole, comments, err := sameDocumentTarget(uri)
		if err != nil {
			return out, err
		}
		if whole {
			in.ns = c14n.Document(doc)
			out.whole = true
		} else {
			el, err := findID(doc, sig, id, idAttrs)
			if err != nil {
				return out, err
			}
			in.ns = c14n.Subtree(el)
			out.element, out.id = el, id
		}
		// A bare "" or "#id" dereference removes comments (XML-DSig
		// 4.4.3.3); a scheme-based XPointer keeps them.
		in.stripComments = !comments
	case strings.HasPrefix(uri, "cid:"):
		if atts == nil {
			return out, fmt.Errorf("%w: %q, and no attachments supplied", xmlsec.ErrAttachmentNotFound, uri)
		}
		att, err := atts.Lookup(uri)
		if err != nil {
			return out, err
		}
		in.octets, in.attachment = att.Body, att
		out.attachment = att
	case resolve != nil && isExternal(uri):
		// XML-DSig 4.4.3.1: an external resource is an octet stream.
		b, err := resolve(uri)
		if err != nil {
			return out, fmt.Errorf("%w: %q: %w", xmlsec.ErrDereference, uri, err)
		}
		in.octets, out.external = b, uri
	default:
		return out, fmt.Errorf("%w: reference URI %q", xmlsec.ErrMalformed, uri)
	}

	if in.ns != nil && len(transforms) == 0 && !implicit {
		return out, fmt.Errorf("%w: same-document reference %q has no canonicalization transform", xmlsec.ErrMalformed, uri)
	}
	if err := in.digest(h, sig, uri, transforms, implicit); err != nil {
		return out, err
	}
	if !in.covers() {
		// A filter dropped part of the target: it is not covered.
		out = dereferenced{}
	}
	if in.token != nil {
		// What was digested is the token, not the reference to it.
		out = dereferenced{token: in.token}
	}
	return out, nil
}

// data is a reference's data object between transforms (XML-DSig 4.4.3.2):
// a node set when ns is non-nil, octets otherwise.
type data struct {
	ns     c14n.NodeSet
	octets []byte

	// stripComments marks a node set from a bare "" or "#id" dereference,
	// which holds no comments: a #WithComments canonicalization of it
	// renders as its plain form.
	stripComments bool

	// attachment is the cid: target, for the SwA transforms.
	attachment *xmlsec.Attachment

	// cut is set once an XPath or XPath Filter 2.0 transform dropped a node
	// of its input, other than the signature's own, or an
	// enveloped-signature transform removed a target within the signature.
	// reparsed marks a node set parsed from octets, whose nodes are not the
	// document's; opaque marks data that no longer shows what of the target
	// it came from: an XSLT output, the text of a node set the base64
	// transform decoded, or a filter over a reparsed node set that dropped
	// something.
	cut      bool
	reparsed bool
	opaque   bool

	// strDeref finds the token of the STR Dereference Transform, and token
	// is the token it digested.
	strDeref tokenDeref
	token    *xdm.Node
}

// covers reports whether the transforms kept all of the data object. A
// filter's input is never more than the dereferenced subtree, or else
// reparsed, so a cut node always lies within it.
func (d *data) covers() bool { return !d.opaque && !d.cut }

// digest applies transforms to d and writes the resulting octets into h;
// sig, uri and implicit are as for digestReference.
func (d *data) digest(h hash.Hash, sig *xdm.Node, uri string, transforms []TransformSpec, implicit bool) error {
	if len(transforms) > MaxTransformsPerReference {
		return fmt.Errorf("%w: %d transforms on %q", xmlsec.ErrLimitExceeded, len(transforms), uri)
	}
	for i, t := range transforms {
		last := i == len(transforms)-1
		switch alg := t.Algorithm; {
		case alg == xmlsec.TransformEnvelopedSignature:
			// XML-DSig 6.6.4: its input is a node set. Octets are not parsed
			// for it, and a node set parsed from octets is refused: "the
			// enveloped signature transform [MUST] be applied only to node
			// sets from the original document", and the parsed tree holds
			// no signature to remove.
			switch f, ok := d.ns.(filtered); {
			case d.ns == nil:
				return fmt.Errorf("%w: enveloped-signature needs a node set", xmlsec.ErrMalformed)
			case d.reparsed:
				return fmt.Errorf("%w: enveloped-signature over a node set parsed from octets", xmlsec.ErrMalformed)
			case ok:
				d.ns = f.without(sig)
			default:
				d.ns = c14n.ExcludeSubtree(d.ns.Root(), sig)
			}
			if within(d.ns.Root(), sig) {
				// The target lies within the signature, such as its own
				// ds:Object: the transform removes all of it, and nothing of
				// it is digested, so it is not covered.
				d.cut = true
			}

		case isC14N(alg):
			if d.ns == nil {
				// XML-DSig 4.4.3.2: octets followed by a transform that
				// requires a node set are parsed, with the same fixed options
				// and limits as any received document.
				tree, err := xmlsec.Parse(d.octets)
				if err != nil {
					return fmt.Errorf("%w: parsing octets for %s: %w", xmlsec.ErrMalformed, alg, err)
				}
				d.ns, d.octets, d.stripComments, d.reparsed = c14n.Document(tree.Root), nil, false, true
			}
			c := c14n.Algorithm(alg)
			if plain, ok := withoutComments[c]; ok && d.stripComments {
				c = plain
			}
			opts := c14n.Options{
				Algorithm:                  c,
				InclusiveNamespacePrefixes: t.InclusiveNamespacePrefixes,
			}
			if last {
				_, err := c14n.DigestNodeSet(h, d.ns, opts)
				return err
			}
			b, err := c14n.BytesNodeSet(d.ns, opts)
			if err != nil {
				return err
			}
			d.ns, d.octets = nil, b

		case alg == xmlsec.TransformBase64:
			// The decoded octets go straight into the digest when nothing
			// follows. They are not character data, so they are not checked
			// for NFC (XML-DSig 8.1.3): only canonical XML is.
			var out bytes.Buffer
			dec := base64Decoder{w: &out}
			if last {
				dec.w = h
				if n, ok := h.(*nfcHash); ok {
					dec.w = n.Hash
				}
			}
			if d.ns != nil {
				// XML-DSig 6.6.2: a node set becomes octets as self::text(),
				// in document order, concatenated. Its elements, attributes,
				// comments and processing instructions are not digested, so
				// nothing of the target is covered.
				eachText(d.ns, dec.write)
				d.opaque = true
			} else {
				out.Grow(len(d.octets) / 4 * 3)
				dec.write(string(d.octets))
			}
			if err := dec.close(); err != nil {
				return fmt.Errorf("%w: base64 transform: %v", xmlsec.ErrMalformed, err)
			}
			if last {
				return nil
			}
			d.ns, d.octets = nil, out.Bytes()

		case alg == xmlsec.TransformAttachmentContentSignature, alg == xmlsec.TransformAttachmentCompleteSignature:
			// SwA profile 5.3 and 5.4.4: the first transform of a cid:
			// reference, over the attachment itself.
			if d.attachment == nil || i > 0 {
				return fmt.Errorf("%w: %s must be the first transform of a cid: reference", xmlsec.ErrMalformed, alg)
			}
			canon, write := swa.Content, swa.WriteContent
			if alg == xmlsec.TransformAttachmentCompleteSignature {
				canon, write = swa.Complete, swa.WriteComplete
			}
			if last {
				// Streamed into the digest, so an XML attachment's
				// canonical form is never held in memory.
				return write(h, d.attachment)
			}
			b, err := canon(d.attachment)
			if err != nil {
				return err
			}
			d.octets = b

		case alg == xmlsec.TransformAttachmentContentOnly, alg == xmlsec.TransformAttachmentComplete:
			// SwA profile 5.5.2: EncryptedData Type URIs, not signature
			// transforms. WS-Security peers refuse them in a signature, so
			// neither is produced nor accepted as one.
			return fmt.Errorf("%w: %s is an EncryptedData Type, not a signature transform; use %s or %s",
				xmlsec.ErrUnsupportedAlgorithm, alg, xmlsec.TransformAttachmentContentSignature, xmlsec.TransformAttachmentCompleteSignature)

		case alg == xmlsec.TransformXPath, alg == xmlsec.TransformXPathFilter2:
			if err := d.filter(t, sig); err != nil {
				return err
			}

		case alg == xmlsec.TransformXSLT:
			var w io.Writer
			if last {
				// Streamed into the digest, not collected first.
				w = h
			}
			if err := d.transformXSLT(t, w); err != nil || last {
				return err
			}

		case alg == xmlsec.TransformSTR:
			return d.digestSTR(h, t, len(transforms) == 1)

		default:
			return fmt.Errorf("%w: transform %s", xmlsec.ErrUnsupportedAlgorithm, alg)
		}
	}
	if d.ns != nil {
		if !implicit {
			return fmt.Errorf("%w: final transform of %q yields a node set, not octets", xmlsec.ErrMalformed, uri)
		}
		_, err := c14n.DigestNodeSet(h, d.ns, c14n.Options{Algorithm: c14n.Inclusive10})
		return err
	}
	h.Write(d.octets)
	return nil
}

// base64Decoder decodes base64 text written to it into w, a chunk at a
// time, ignoring every octet outside the base64 alphabet and the pad (RFC
// 2045 section 6.8, which XML-DSig 6.6.2 names). That is what filtering the
// runes of the text would do: no UTF-8 sequence, valid or not, holds an
// ASCII octet. Chunks are whole quanta, so each decodes as it would within
// the whole text, except that a pad ending a chunk with text after it is
// trailing garbage there.
type base64Decoder struct {
	w   io.Writer
	buf [4096]byte
	n   int // octets in buf
	at  int // octets of filtered text before buf
	out [3072]byte
	err error
}

func (d *base64Decoder) write(s string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '=') {
			continue
		}
		if d.n == len(d.buf) {
			if d.flush(true); d.err != nil {
				return
			}
		}
		d.buf[d.n] = c
		d.n++
	}
}

// flush decodes buf, which ends the text unless more is set.
func (d *base64Decoder) flush(more bool) {
	if d.err != nil {
		return
	}
	k, err := base64.StdEncoding.Decode(d.out[:], d.buf[:d.n])
	if err == nil && more && d.buf[d.n-1] == '=' {
		err = base64.CorruptInputError(d.n - 1)
	}
	if err != nil {
		d.err = err.(base64.CorruptInputError) + base64.CorruptInputError(d.at)
		return
	}
	_, _ = d.w.Write(d.out[:k]) // a hash or a bytes.Buffer, which never fail
	d.at, d.n = d.at+d.n, 0
}

// close decodes what is left and reports the first error.
func (d *base64Decoder) close() error {
	d.flush(false)
	return d.err
}

// eachText calls f with each text node of ns in document order.
func eachText(ns c14n.NodeSet, f func(string)) {
	var walk func(n *xdm.Node)
	walk = func(n *xdm.Node) {
		if n.Kind() == xdm.KindText && ns.Contains(n) {
			f(n.Value())
		}
		for c := range n.Children() {
			walk(c)
		}
	}
	walk(ns.Root())
}
