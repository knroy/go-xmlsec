package xmlsec

import (
	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2/internal/xmltree"
)

// Document is a document that this module adds to: dsig.Sign placing a
// signature, wss.NewHeader and its Header, and wss.AssignID.
//
// A parsed go-xml tree cannot be changed, so each change builds a new tree,
// and Root returns the latest. Nodes of an earlier tree, such as an element
// found in the parsed document before a header was added, are still
// accepted wherever a Document is passed beside them; Node finds their
// counterpart in the latest tree, for a function that takes only a tree,
// such as xenc.EncryptElement or dsig.Verify.
//
// A Document is not safe for concurrent use.
type Document struct {
	d *xmltree.Doc
}

func init() {
	xmltree.DocOf = func(doc any) *xmltree.Doc {
		if d, _ := doc.(*Document); d != nil {
			return d.d
		}
		return nil
	}
}

// NewDocument starts a Document at the tree n belongs to, usually the
// document node of a tree from Parse: NewDocument(tree.Root).
func NewDocument(n *xdm.Node) *Document {
	return &Document{d: xmltree.NewDoc(n)}
}

// Root returns the root of the latest tree: the document node, for a
// Document started from a parsed document.
func (d *Document) Root() *xdm.Node { return d.d.Root() }

// Node returns n's counterpart in the latest tree: n itself if it is there,
// or nil if n was never part of d or a change removed it.
func (d *Document) Node(n *xdm.Node) *xdm.Node { return d.d.Node(n) }
