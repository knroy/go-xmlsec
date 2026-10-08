package wss

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Header wraps a wsse:Security element under construction. Make one with
// NewHeader: the methods of a nil or zero Header return an error, and its
// Element is nil.
type Header struct {
	doc *xdm.Node
	el  *xdm.Node
}

// check refuses a Header that NewHeader did not make.
func (h *Header) check() error {
	if h == nil || h.el == nil {
		return errors.New("wss: Header not made by NewHeader")
	}
	return nil
}

// NewHeader creates a wsse:Security element in the SOAP header of doc,
// creating the SOAP Header if there is none.
//
// actor is the SOAP role the header targets; empty means none, the ultimate
// receiver. WS-Security allows one header per recipient (SOAP Message
// Security 1.1.1 section 5), so a second header for the same actor is
// refused. For SOAP 1.2, the ultimateReceiver role is the same recipient as
// no role (SOAP 1.2 Part 1 section 5.2.2) and counts as a duplicate of it.
// SOAP 1.1's actor "next" is a different recipient, the first node to
// process the message, and does not.
//
// mustUnderstand sets the SOAP mustUnderstand attribute. The SOAP attributes
// take the Envelope's prefix. An Envelope in the default namespace has none
// to lend, and an unprefixed attribute is in no namespace, so is not a SOAP
// attribute at all; the header then declares its own prefix, soap for SOAP
// 1.1 and env for SOAP 1.2.
//
// Elements are added ahead of the existing content, as WS-Security
// specifies; see Prepend.
func NewHeader(doc *xdm.Node, soapNS string, actor string, mustUnderstand bool) (*Header, error) {
	if soapNS != xmlsec.NSSOAP11 && soapNS != xmlsec.NSSOAP12 {
		return nil, fmt.Errorf("wss: unknown SOAP namespace %q", soapNS)
	}
	env := xmltree.DocumentElement(doc)
	if env == nil || !env.IsElement(soapNS, "Envelope") {
		return nil, errors.New("wss: document element is not a SOAP Envelope")
	}

	var hdr *xdm.Node
	if kids := env.ChildElements(); len(kids) > 0 && kids[0].IsElement(soapNS, "Header") {
		hdr = kids[0]
	} else {
		hdr = xmltree.Element(env, env.Name.Prefix, soapNS, "Header")
		// AppendChild is the only way to link a node into the tree; move it
		// to the front, where the SOAP Header belongs.
		copy(env.Children[1:], env.Children[:len(env.Children)-1])
		env.Children[0] = hdr
	}

	if len(securityHeaders(hdr, soapNS, actor)) > 0 {
		return nil, fmt.Errorf("wss: a wsse:Security header for actor %q already exists", actor)
	}
	actorAttr := actorAttribute(soapNS)

	// Built detached and attached last, so its own namespace declarations
	// cannot conflict with an ancestor's.
	sec := xmltree.Element(nil, "wsse", xmlsec.NSWSSE, "Security")
	sec.AddNamespace("wsse", xmlsec.NSWSSE)
	p := env.Name.Prefix
	if p == "" {
		p = "soap"
		if soapNS == xmlsec.NSSOAP12 {
			p = "env"
		}
		sec.AddNamespace(p, soapNS)
	}
	if mustUnderstand {
		v := "1"
		if soapNS == xmlsec.NSSOAP12 {
			v = "true"
		}
		xmltree.SetAttr(sec, p, soapNS, "mustUnderstand", v)
	}
	if actor != "" {
		xmltree.SetAttr(sec, p, soapNS, actorAttr, actor)
	}
	hdr.AppendChild(sec)
	return &Header{doc: doc, el: sec}, nil
}

// Prepend places an already-constructed element, such as a ds:Signature, an
// xenc:EncryptedKey or an xenc:ReferenceList, ahead of the existing content
// of the security header. WS-Security requires this of every signing and
// encryption step (SOAP Message Security 1.1.1 sections 5, 8.2 and 9): the
// header then lists the steps last-first, and a receiver processing it in
// order meets no forward dependency. Sign and Prepend the signature, then
// Prepend the EncryptedKey, and the receiver decrypts first and verifies
// second.
//
// Two kinds of element stay ahead of it:
//
//   - a wsu:Timestamp heading the header. It depends on nothing, and a
//     receiver can check it before any cryptographic work.
//   - every token in the header that el references by wsse:Reference, so a
//     token precedes each SecurityTokenReference to it (Basic Security
//     Profile R5205). A token must be in the document before signing, since
//     the signature names it; AddBinarySecurityToken puts it first, and
//     Prepend keeps it there.
//
// An xenc:EncryptedKey must precede every xenc:EncryptedData its
// ReferenceList names in the same header (R3208). If a token it references
// follows such an EncryptedData, Prepend refuses and leaves the header
// unchanged.
func (h *Header) Prepend(el *xdm.Node) error {
	if err := h.check(); err != nil {
		return err
	}
	if el == nil || el.Kind != xdm.KindElement || el.Parent != nil {
		return errors.New("wss: Prepend needs a detached element")
	}
	tokens := refs(el, xmlsec.NSWSSE, "Reference")
	i := h.front()
	for j, c := range h.el.Children {
		if hasAnyID(c, tokens) {
			i = max(i, j+1)
		}
	}
	data := refs(el, xmlsec.NSXEnc, "DataReference")
	for _, c := range h.el.Children[:i] {
		if hasAnyID(c, data) {
			return fmt.Errorf("wss: %s would follow an xenc:EncryptedData it lists", el.Name.Local)
		}
	}
	h.insert(i, el)
	return nil
}

// Append places an already-constructed element at the end of the security
// header, for a caller that orders the header itself. Prepend gives the
// order WS-Security specifies.
func (h *Header) Append(el *xdm.Node) error {
	if err := h.check(); err != nil {
		return err
	}
	if el == nil || el.Parent != nil {
		return errors.New("wss: Append needs a detached node")
	}
	h.el.AppendChild(el)
	return nil
}

// Element returns the wsse:Security element, or nil for a nil or zero
// Header.
func (h *Header) Element() *xdm.Node {
	if h == nil {
		return nil
	}
	return h.el
}

// front returns where a prepended element goes: first, or after a leading
// wsu:Timestamp.
func (h *Header) front() int {
	for i, c := range h.el.Children {
		if c.Kind == xdm.KindElement {
			if c.IsElement(xmlsec.NSWSU, "Timestamp") {
				return i + 1
			}
			break
		}
	}
	return 0
}

// insert links el as the i'th child of the header.
func (h *Header) insert(i int, el *xdm.Node) {
	h.el.AppendChild(el)
	kids := h.el.Children
	copy(kids[i+1:], kids[i:len(kids)-1])
	kids[i] = el
}

// refs returns the local IDs that the URI of each ns:local element inside el
// names, such as those of its wsse:Reference elements.
func refs(el *xdm.Node, ns, local string) map[string]bool {
	out := map[string]bool{}
	xmltree.Walk(el, func(e *xdm.Node) {
		if id, ok := strings.CutPrefix(e.AttrValue("URI"), "#"); ok && e.IsElement(ns, local) {
			out[id] = true
		}
	})
	return out
}

// hasAnyID reports whether n carries one of ids as its wsu:Id, xml:id or
// unqualified Id.
func hasAnyID(n *xdm.Node, ids map[string]bool) bool {
	for _, a := range n.Attrs {
		if isAnyID(a.Name) && ids[a.Value] {
			return true
		}
	}
	return false
}

// actorAttribute is the name of the SOAP attribute that targets a header.
func actorAttribute(soapNS string) string {
	if soapNS == xmlsec.NSSOAP12 {
		return "role"
	}
	return "actor"
}

// securityHeaders returns the wsse:Security children of the SOAP Header hdr
// that target actor. For SOAP 1.2, the ultimateReceiver role is the same
// recipient as no role (SOAP 1.2 Part 1 section 5.2.2).
func securityHeaders(hdr *xdm.Node, soapNS, actor string) []*xdm.Node {
	recipient := func(a string) string {
		if soapNS == xmlsec.NSSOAP12 && a == roleUltimateReceiver {
			return ""
		}
		return a
	}
	var out []*xdm.Node
	for _, e := range hdr.ChildElements() {
		if e.IsElement(xmlsec.NSWSSE, "Security") && recipient(xmltree.AttrValue(e, soapNS, actorAttribute(soapNS))) == recipient(actor) {
			out = append(out, e)
		}
	}
	return out
}
