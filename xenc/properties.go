package xenc

import (
	"errors"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
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

// newKeyInfo appends a ds:KeyInfo to parent, an EncryptedData or
// EncryptedKey, and returns it. Children are appended in schema order.
func newKeyInfo(parent *xdm.Node) *xdm.Node {
	return nsElement(parent, "ds", xmlsec.NSDSig, "KeyInfo")
}

// withChild returns a copy of parent, a detached EncryptedData or
// EncryptedKey, with el among its children in its schema place: before
// the first child that follows it in schema order.
func withChild(parent, el *xdm.Node) *xdm.Node {
	i := 0
	for k := range parent.Children() {
		if rank(k) > rank(el) {
			break
		}
		i++
	}
	var e xmltree.Edits
	e.Insert(parent, i, el)
	root, _ := xmltree.Rebuild(parent, &e)
	return root
}

// checkDataAttrs refuses options that do not apply to an EncryptedData
// of Type typ.
func checkDataAttrs(typ string, opts EncryptOptions) error {
	switch {
	case opts.Type != "" && opts.Type != typ:
		return fmt.Errorf("xenc: EncryptOptions.Type %q: this function encrypts Type %q", opts.Type, typ)
	case opts.CipherReferenceURI != "":
		return errors.New("xenc: EncryptOptions.CipherReferenceURI is only for EncryptOctets")
	case opts.MimeType != "" && (typ == xmlsec.TransformAttachmentContentOnly || typ == xmlsec.TransformAttachmentComplete):
		return errors.New("xenc: EncryptAttachment takes MimeType from the attachment's Content-Type")
	}
	for _, p := range opts.EncryptionProperties {
		if p == nil || !p.IsElement(xmlsec.NSXEnc, "EncryptionProperty") {
			return errors.New("xenc: EncryptOptions.EncryptionProperties must be xenc:EncryptionProperty elements")
		}
	}
	return nil
}

// addProperties appends opts.EncryptionProperties to ed, whose
// xenc:CipherData is complete: they follow it in schema order.
func addProperties(ed *xdm.Node, opts EncryptOptions) error {
	if len(opts.EncryptionProperties) == 0 {
		return nil
	}
	props := element(ed, "EncryptionProperties")
	for _, p := range opts.EncryptionProperties {
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
		props.AppendCopy(tree.Root.FirstChild())
	}
	return nil
}
