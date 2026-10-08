package xenc

import (
	"errors"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// schemaOrder is the order of the children of xenc:EncryptedData and
// xenc:EncryptedKey (sections 3.4 and 3.5.1).
var schemaOrder = []xdm.QName{
	{URI: xmlsec.NSXEnc, Local: "EncryptionMethod"},
	{URI: xmlsec.NSDSig, Local: "KeyInfo"},
	{URI: xmlsec.NSXEnc, Local: "CipherData"},
	{URI: xmlsec.NSXEnc, Local: "EncryptionProperties"},
	{URI: xmlsec.NSXEnc, Local: "ReferenceList"},
	{URI: xmlsec.NSXEnc, Local: "CarriedKeyName"},
}

func rank(n *xdm.Node) int {
	return slices.IndexFunc(schemaOrder, func(q xdm.QName) bool { return n.IsElement(q.URI, q.Local) })
}

// place moves parent's last child, just appended, before the first child
// that follows it in schema order.
func place(parent *xdm.Node) {
	kids := parent.Children
	last := kids[len(kids)-1]
	if i := slices.IndexFunc(kids, func(k *xdm.Node) bool { return rank(k) > rank(last) }); i >= 0 {
		copy(kids[i+1:], kids[i:len(kids)-1])
		kids[i] = last
	}
}

// newKeyInfo adds a ds:KeyInfo to parent, an EncryptedData or
// EncryptedKey, in its schema place, and returns it.
func newKeyInfo(parent *xdm.Node) *xdm.Node {
	ki := nsElement(parent, "ds", xmlsec.NSDSig, "KeyInfo")
	place(parent)
	return ki
}

// dataAttrs sets the Type ("" for none), MimeType and Encoding attributes
// of ed, a new EncryptedData, and appends opts.EncryptionProperties.
func dataAttrs(ed *xdm.Node, typ string, opts EncryptOptions) error {
	switch {
	case opts.Type != "" && opts.Type != typ:
		return fmt.Errorf("xenc: EncryptOptions.Type %q: this function encrypts Type %q", opts.Type, typ)
	case opts.CipherReferenceURI != "":
		return errors.New("xenc: EncryptOptions.CipherReferenceURI is only for EncryptOctets")
	case opts.MimeType != "" && (typ == xmlsec.TransformAttachmentContentOnly || typ == xmlsec.TransformAttachmentComplete):
		return errors.New("xenc: EncryptAttachment takes MimeType from the attachment's Content-Type")
	}
	for _, a := range [][2]string{{"Type", typ}, {"MimeType", opts.MimeType}, {"Encoding", opts.Encoding}} {
		if a[1] != "" {
			xmltree.SetAttr(ed, "", "", a[0], a[1])
		}
	}
	if len(opts.EncryptionProperties) == 0 {
		return nil
	}
	props := element(ed, "EncryptionProperties")
	for _, p := range opts.EncryptionProperties {
		if p == nil || !p.IsElement(xmlsec.NSXEnc, "EncryptionProperty") {
			return errors.New("xenc: EncryptOptions.EncryptionProperties must be xenc:EncryptionProperty elements")
		}
		// A copy, through its canonical form: p keeps its place, and the
		// copy declares every namespace in scope where p stands.
		b, err := c14n.Bytes(p, c14n.Options{Algorithm: c14n.Inclusive10WithComments})
		if err != nil {
			return err
		}
		tree, err := xmlsec.Parse(b)
		if err != nil {
			return fmt.Errorf("xenc: EncryptionProperty: %w", err)
		}
		props.AppendChild(tree.Root.Children[0])
	}
	return nil
}
