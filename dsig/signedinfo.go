package dsig

import (
	"fmt"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// parsedSignature is a received ds:Signature, structurally validated.
type parsedSignature struct {
	signedInfo *xdm.Node
	c14n       c14n.Options
	sigAlg     string
	sigMethod  *xdm.Node

	refs    []parsedReference
	value   []byte
	keyInfo *xdm.Node // nil when absent
}

type parsedReference struct {
	el         *xdm.Node
	uri, typ   string
	omitted    bool // no URI attribute: XML-DSig 4.4.3.1
	transforms []TransformSpec
	digestAlg  string
	digest     []byte
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{xmlsec.ErrMalformed}, args...)...)
}

// parseSignature reads ds:Signature strictly: SignedInfo, SignatureValue,
// optional KeyInfo, then only ds:Object. maxRefs is enforced before any
// reference is parsed.
func parseSignature(sig *xdm.Node, maxRefs int) (*parsedSignature, error) {
	kids := sig.ChildElements()
	if len(kids) < 2 || !kids[0].IsElement(xmlsec.NSDSig, "SignedInfo") || !kids[1].IsElement(xmlsec.NSDSig, "SignatureValue") {
		return nil, malformed("ds:Signature must begin with ds:SignedInfo, ds:SignatureValue")
	}
	p := &parsedSignature{signedInfo: kids[0]}
	var err error
	if p.value, err = xmltree.Base64(kids[1]); err != nil {
		return nil, malformed("ds:SignatureValue: %v", err)
	}
	for i, k := range kids[2:] {
		switch {
		case i == 0 && k.IsElement(xmlsec.NSDSig, "KeyInfo"):
			p.keyInfo = k
		case k.IsElement(xmlsec.NSDSig, "Object"):
		default:
			return nil, malformed("unexpected %s in ds:Signature", k.Name.Local)
		}
	}

	si := p.signedInfo.ChildElements()
	if len(si) < 3 || !si[0].IsElement(xmlsec.NSDSig, "CanonicalizationMethod") || !si[1].IsElement(xmlsec.NSDSig, "SignatureMethod") {
		return nil, malformed("ds:SignedInfo must hold CanonicalizationMethod, SignatureMethod, Reference+")
	}
	cm, err := parseTransform(si[0])
	if err != nil {
		return nil, err
	}
	p.c14n = c14n.Options{Algorithm: c14n.Algorithm(cm.Algorithm), InclusiveNamespacePrefixes: cm.InclusiveNamespacePrefixes}
	// Children are checked after the allow-list, in verify, so that an HMAC
	// method (whose HMACOutputLength is a child) not allowed is reported as
	// the disallowed algorithm it is rather than as malformed.
	p.sigAlg = si[1].AttrValue("Algorithm")
	p.sigMethod = si[1]

	refs := si[2:]
	if len(refs) > maxRefs {
		return nil, fmt.Errorf("%w: %d references, limit %d", xmlsec.ErrLimitExceeded, len(refs), maxRefs)
	}
	for _, r := range refs {
		ref, err := parseReference(r)
		if err != nil {
			return nil, err
		}
		p.refs = append(p.refs, ref)
	}
	return p, nil
}

func parseReference(r *xdm.Node) (parsedReference, error) {
	ref := parsedReference{el: r, typ: r.AttrValue("Type")}
	if !r.IsElement(xmlsec.NSDSig, "Reference") {
		return ref, malformed("unexpected %s in ds:SignedInfo", r.Name.Local)
	}
	if uri := r.Attr("", "URI"); uri != nil {
		ref.uri = uri.Value
	} else {
		ref.omitted = true
	}

	kids := r.ChildElements()
	if len(kids) > 0 && kids[0].IsElement(xmlsec.NSDSig, "Transforms") {
		ts := kids[0].ChildElements()
		if len(ts) > MaxTransformsPerReference {
			return ref, fmt.Errorf("%w: %d transforms", xmlsec.ErrLimitExceeded, len(ts))
		}
		for _, t := range ts {
			if !t.IsElement(xmlsec.NSDSig, "Transform") {
				return ref, malformed("unexpected %s in ds:Transforms", t.Name.Local)
			}
			spec, err := parseTransform(t)
			if err != nil {
				return ref, err
			}
			ref.transforms = append(ref.transforms, spec)
		}
		kids = kids[1:]
	}
	if len(kids) != 2 || !kids[0].IsElement(xmlsec.NSDSig, "DigestMethod") || !kids[1].IsElement(xmlsec.NSDSig, "DigestValue") {
		return ref, malformed("ds:Reference must end with DigestMethod, DigestValue")
	}
	ref.digestAlg = kids[0].AttrValue("Algorithm")
	var err error
	if ref.digest, err = xmltree.Base64(kids[1]); err != nil {
		return ref, malformed("ds:DigestValue: %v", err)
	}
	return ref, nil
}

// parseTransform reads a ds:Transform or ds:CanonicalizationMethod. The only
// child accepted is ec:InclusiveNamespaces, and only under an exclusive
// algorithm.
func parseTransform(t *xdm.Node) (TransformSpec, error) {
	spec := TransformSpec{Algorithm: t.AttrValue("Algorithm")}
	for _, k := range t.ChildElements() {
		if !k.IsElement(xmlsec.NSExcC14N, "InclusiveNamespaces") || !c14n.Algorithm(spec.Algorithm).Exclusive() ||
			spec.InclusiveNamespacePrefixes != nil {
			// Unknown children are refused rather than ignored: an XPath or
			// XSLT transform carries its program as a child.
			return spec, malformed("unexpected %s under %s", k.Name.Local, t.Name.Local)
		}
		spec.InclusiveNamespacePrefixes = c14n.ParsePrefixList(k.AttrValue("PrefixList"))
		if spec.InclusiveNamespacePrefixes == nil {
			spec.InclusiveNamespacePrefixes = []string{}
		}
	}
	return spec, nil
}
