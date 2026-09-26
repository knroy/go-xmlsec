package dsig

import (
	"encoding/base64"
	"fmt"
	"hash"
	"net/url"
	"regexp"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/swa"
	"github.com/knroy/go-xmlsec/wss"
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
		case isC14N(a) || a == xmlsec.TransformBase64 || a == xmlsec.TransformXSLT:
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
}

// isExternal reports whether uri is absolute, the only kind a URIResolver
// is given: a relative reference would need a base URI this library does
// not have.
func isExternal(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && u.IsAbs()
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
// when nil, such a reference is refused.
func digestReference(h hash.Hash, doc, sig *xdm.Node, uri string, transforms []TransformSpec,
	atts xmlsec.AttachmentSet, implicit bool, idAttrs []xdm.QName, resolve xmlsec.URIResolver) (dereferenced, error) {

	var (
		out dereferenced
		in  data
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
			el, err := wss.FindByID(doc, id, idAttrs...)
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
	if !in.covers(out.element) {
		// A filter dropped part of the target: it is not covered.
		out = dereferenced{}
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

	// cut holds the nodes of the document an XPath or XPath Filter 2.0
	// transform dropped, other than the signature's own. reparsed marks a
	// node set parsed from octets, whose nodes are not the document's;
	// opaque marks data that no longer shows what of the target it came
	// from: an XSLT output, or a filter over a reparsed node set that
	// dropped something.
	cut      []*xdm.Node
	reparsed bool
	opaque   bool
}

// covers reports whether the transforms kept all of el's subtree, or with
// el nil, all of the data object.
func (d *data) covers(el *xdm.Node) bool {
	if d.opaque {
		return false
	}
	for _, x := range d.cut {
		if el == nil || within(x, el) {
			return false
		}
	}
	return true
}

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
			// for it: the parsed tree would hold no signature to remove.
			switch f, ok := d.ns.(filtered); {
			case d.ns == nil:
				return fmt.Errorf("%w: enveloped-signature needs a node set", xmlsec.ErrMalformed)
			case ok:
				d.ns = f.without(sig)
			default:
				d.ns = c14n.ExcludeSubtree(d.ns.Root(), sig)
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
				d.ns, d.stripComments, d.reparsed = c14n.Document(tree.Root), false, true
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
			if d.ns != nil {
				// XML-DSig 6.6.2: a node set becomes octets as self::text(),
				// in document order, concatenated.
				d.ns, d.octets = nil, []byte(textOf(d.ns))
			}
			b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(d.octets)), ""))
			if err != nil {
				return fmt.Errorf("%w: base64 transform: %v", xmlsec.ErrMalformed, err)
			}
			d.octets = b

		case alg == xmlsec.TransformAttachmentContentSignature, alg == xmlsec.TransformAttachmentCompleteSignature:
			// SwA profile 5.3 and 5.4.4: the first transform of a cid:
			// reference, over the attachment itself.
			if d.attachment == nil || i > 0 {
				return fmt.Errorf("%w: %s must be the first transform of a cid: reference", xmlsec.ErrMalformed, alg)
			}
			canon := swa.Content
			if alg == xmlsec.TransformAttachmentCompleteSignature {
				canon = swa.Complete
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
			if err := d.transformXSLT(t); err != nil {
				return err
			}

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

// textOf concatenates the text nodes of ns in document order.
func textOf(ns c14n.NodeSet) string {
	var b strings.Builder
	var walk func(n *xdm.Node)
	walk = func(n *xdm.Node) {
		if n.Kind == xdm.KindText && ns.Contains(n) {
			b.WriteString(n.Value)
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(ns.Root())
	return b.String()
}
