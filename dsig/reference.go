package dsig

import (
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/wss"
)

// impliesC14N reports whether a reference relies on the implicit Canonical
// XML 1.0 of XML-DSig 4.4.3.2: a same-document URI and no canonicalization
// among its transforms, so the chain ends in a node set.
func impliesC14N(uri string, transforms []TransformSpec) bool {
	if uri != "" && !strings.HasPrefix(uri, "#") {
		return false
	}
	for _, t := range transforms {
		if isC14N(t.Algorithm) {
			return false
		}
	}
	return true
}

// dereferenced is what a reference actually covered, derived while
// digesting it rather than inferred from its URI.
type dereferenced struct {
	element    *xdm.Node          // "#id" target
	attachment *xmlsec.Attachment // cid: target
	whole      bool               // "" target
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
// xml:id.
func digestReference(h hash.Hash, doc, sig *xdm.Node, uri string, transforms []TransformSpec,
	atts xmlsec.AttachmentSet, implicit bool, idAttrs []xdm.QName) (dereferenced, error) {

	var (
		out    dereferenced
		ns     c14n.NodeSet
		octets []byte
	)
	switch {
	case uri == "":
		ns = c14n.Document(doc)
		out.whole = true
	case strings.HasPrefix(uri, "#"):
		el, err := wss.FindByIDAttributes(doc, uri[1:], idAttrs...)
		if err != nil {
			return out, err
		}
		ns = c14n.Subtree(el)
		out.element = el
	case strings.HasPrefix(uri, "cid:"):
		if atts == nil {
			return out, fmt.Errorf("%w: %q, and no attachments supplied", xmlsec.ErrAttachmentNotFound, uri)
		}
		att, err := atts.Lookup(uri)
		if err != nil {
			return out, err
		}
		octets = att.Body
		out.attachment = att
	default:
		return out, fmt.Errorf("%w: reference URI %q", xmlsec.ErrMalformed, uri)
	}

	if ns != nil && len(transforms) == 0 && !implicit {
		return out, fmt.Errorf("%w: same-document reference %q has no canonicalization transform", xmlsec.ErrMalformed, uri)
	}
	if len(transforms) > MaxTransformsPerReference {
		return out, fmt.Errorf("%w: %d transforms on %q", xmlsec.ErrLimitExceeded, len(transforms), uri)
	}

	for i, t := range transforms {
		last := i == len(transforms)-1
		switch alg := t.Algorithm; {
		case alg == xmlsec.TransformEnvelopedSignature:
			if ns == nil {
				return out, fmt.Errorf("%w: enveloped-signature needs a node set", xmlsec.ErrMalformed)
			}
			ns = c14n.ExcludeSubtree(ns.Root(), sig)

		case isC14N(alg):
			if ns == nil {
				return out, fmt.Errorf("%w: canonicalization needs a node set", xmlsec.ErrMalformed)
			}
			// A bare "" or "#id" dereference removes comments (XML-DSig
			// 4.4.3.3), so the #WithComments variants render the same as
			// their plain forms here.
			c := c14n.Algorithm(alg)
			if plain, ok := withoutComments[c]; ok {
				c = plain
			}
			opts := c14n.Options{
				Algorithm:                  c,
				InclusiveNamespacePrefixes: t.InclusiveNamespacePrefixes,
			}
			if last {
				_, err := c14n.DigestNodeSet(h, ns, opts)
				return out, err
			}
			b, err := c14n.BytesNodeSet(ns, opts)
			if err != nil {
				return out, err
			}
			ns, octets = nil, b

		case alg == xmlsec.TransformBase64:
			if ns != nil {
				return out, fmt.Errorf("%w: base64 needs an octet stream", xmlsec.ErrMalformed)
			}
			b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(octets)), ""))
			if err != nil {
				return out, fmt.Errorf("%w: base64 transform: %v", xmlsec.ErrMalformed, err)
			}
			octets = b

		case alg == xmlsec.TransformAttachmentContentOnly:
			// The identity on the body octets. No canonicalization of any
			// kind, even when the body is XML.
			if out.attachment == nil || ns != nil {
				return out, fmt.Errorf("%w: %s applies only to a cid: reference", xmlsec.ErrMalformed, alg)
			}

		case alg == xmlsec.TransformXSLT, alg == xmlsec.TransformXPath, alg == xmlsec.TransformXPathFilter2:
			return out, fmt.Errorf("%w: %s", xmlsec.ErrTransformRefused, alg)

		default:
			// Attachment-Complete lands here until its MIME header
			// canonicalization is implemented.
			return out, fmt.Errorf("%w: transform %s", xmlsec.ErrUnsupportedAlgorithm, alg)
		}
	}
	if ns != nil {
		if !implicit {
			return out, fmt.Errorf("%w: final transform of %q yields a node set, not octets", xmlsec.ErrMalformed, uri)
		}
		_, err := c14n.DigestNodeSet(h, ns, c14n.Options{Algorithm: c14n.Inclusive10})
		return out, err
	}
	h.Write(octets)
	return out, nil
}
