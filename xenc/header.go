package xenc

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptHeader replaces block, a SOAP header block (a direct child of a
// SOAP 1.1 or 1.2 Header), with a wsse11:EncryptedHeader holding an
// xenc:EncryptedData of Type Element encrypted as EncryptElement does, and
// returns the resulting document octets. doc itself is left unmodified.
//
// security is the wsse:Security header whose xenc:ReferenceList or
// xenc:EncryptedKey will reference the EncryptedData. WS-Security 1.1.1
// section 9.4.3 requires that its SOAP mustUnderstand and actor (1.1) or
// role and relay (1.2) attributes be copied to the EncryptedHeader, so a
// SOAP node treats the EncryptedHeader as the security header's own; the
// block's own attributes are encrypted with it, which is the point of
// EncryptedHeader. WSS4J copies them the same way. security must not be
// block.
//
// The Basic Security Profile requires an Id on the EncryptedData or a
// wsu:Id on the EncryptedHeader (R5624, R5627), for a DataReference to
// name. With opts.DataID empty, the EncryptedData gets a random Id, "id-"
// and 32 hex digits, found in the output; set DataID to know it in
// advance, as a ReferenceList built before encrypting needs.
func EncryptHeader(doc, block, security *xdm.Node, sessionKey []byte, opts EncryptOptions) ([]byte, error) {
	if err := checkTarget(doc, block); err != nil {
		return nil, err
	}
	if !isSOAP(block.Parent, "Header") {
		return nil, errors.New("xenc: EncryptHeader needs a SOAP header block")
	}
	if security == nil || !security.IsElement(xmlsec.NSWSSE, "Security") || security == block || security.Root() != doc.Root() {
		return nil, errors.New("xenc: EncryptHeader needs the referencing wsse:Security header, other than block")
	}
	if opts.DataID == "" {
		opts.DataID = randomID()
	}
	return replaceElement(doc, block, sessionKey, opts, func(ed *xdm.Node) (*xdm.Node, error) {
		eh := nsElement(nil, "wsse11", xmlsec.NSWSSE11, "EncryptedHeader")
		eh.AppendChild(ed)
		// Declare against what is in scope where eh will sit; emitWith
		// links it there properly.
		eh.Parent = block.Parent
		for _, a := range security.Attrs {
			if (a.Name.URI == xmlsec.NSSOAP11 || a.Name.URI == xmlsec.NSSOAP12) &&
				(a.Name.Local == "mustUnderstand" || a.Name.Local == "actor" || a.Name.Local == "role" || a.Name.Local == "relay") {
				if err := xmltree.Declare(eh, a.Name.Prefix, a.Name.URI); err != nil {
					return nil, err
				}
				xmltree.SetAttr(eh, a.Name.Prefix, a.Name.URI, a.Name.Local, a.Value)
			}
		}
		return eh, nil
	})
}

// randomID returns "id-" and 32 hex digits from crypto/rand, an NCName.
// ponytail: 128 random bits are not checked against the document's IDs;
// a collision is as likely as guessing a key.
func randomID() string {
	var b [16]byte
	rand.Read(b[:])
	return "id-" + hex.EncodeToString(b[:])
}

// DecryptHeader decrypts eh, a wsse11:EncryptedHeader in doc, as SOAP
// Message Security 1.1.1 section 9.4.4 processes one, and returns the
// document octets with eh replaced by the header block it held. doc itself
// is left unmodified. The output is in canonical form
// (Inclusive10WithComments), as EncryptHeader's is.
//
// eh must be a SOAP header block holding exactly one xenc:EncryptedData,
// and nothing else but whitespace (Basic Security Profile R3230), of Type
// Element. The EncryptedData is decrypted as DecryptData does, under opts;
// find its key with FindEncryptedKey. The plaintext is parsed as
// xmlsec.Parse parses, DOCTYPE refused, in the context of eh: the
// namespaces in scope there are in scope for it (XML Encryption 1.1
// section 4.5.4). It must be exactly one element. A plaintext that does
// not parse, or is not one element, is the same xmlsec.ErrDecryptionFailed
// a wrong key gives, since with CBC data the difference is an oracle.
//
// The block keeps every namespace binding it had in scope, declared on it
// where eh's context differs from the SOAP Header's; that includes eh's own
// declarations, such as its wsse11 prefix. The decrypted block
// can be another EncryptedHeader (section 9.4.3); decrypt that in turn.
func DecryptHeader(doc, eh *xdm.Node, sessionKey []byte, opts DecryptOptions) ([]byte, error) {
	if err := checkTarget(doc, eh); err != nil {
		return nil, err
	}
	if !eh.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") || !isSOAP(eh.Parent, "Header") {
		return nil, malformed("not a wsse11:EncryptedHeader header block")
	}
	var ed *xdm.Node
	for _, c := range eh.Children {
		switch {
		case c.Kind == xdm.KindText && strings.Trim(c.Value, " \t\r\n") == "":
		case ed == nil && c.IsElement(xmlsec.NSXEnc, "EncryptedData"):
			ed = c
		default:
			return nil, malformed("a wsse11:EncryptedHeader must hold exactly one xenc:EncryptedData (BSP R3230)")
		}
	}
	if ed == nil {
		return nil, malformed("a wsse11:EncryptedHeader must hold exactly one xenc:EncryptedData (BSP R3230)")
	}
	if typ := ed.AttrValue("Type"); typ != TypeElement {
		return nil, malformed("the xenc:EncryptedData of a wsse11:EncryptedHeader has Type %q, not Element", typ)
	}
	pt, err := DecryptData(ed, sessionKey, opts)
	if err != nil {
		return nil, err
	}
	nodes, err := parseIn(pt, eh)
	if err != nil || len(nodes) != 1 || nodes[0].Kind != xdm.KindElement {
		return nil, errDecrypt
	}
	// Declare on the block what eh's context binds, so it keeps its
	// meaning under eh's parent.
	block := nodes[0]
	ns := eh.InScopeNamespaces()
	for _, p := range slices.Sorted(maps.Keys(ns)) {
		if p != "xml" && ns[p] != "" && !slices.ContainsFunc(block.Namespaces, func(n *xdm.Node) bool { return n.Name.Local == p }) {
			block.AddNamespace(p, ns[p])
		}
	}
	kids := slices.Clone(eh.Parent.Children)
	kids[slices.Index(kids, eh)] = block
	return emitWith(doc, eh.Parent, kids, block)
}
