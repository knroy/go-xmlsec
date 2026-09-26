package wss

import (
	"errors"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// Header wraps a wsse:Security element under construction.
type Header struct {
	doc *xdm.Node
	el  *xdm.Node
}

// NewHeader creates a wsse:Security element in the SOAP header of doc,
// creating the SOAP Header if there is none.
//
// actor is the SOAP role the header targets; empty means none.
// mustUnderstand sets the SOAP mustUnderstand attribute.
//
// Callers add tokens, signatures and encrypted keys in the order the
// WS-Security specification requires: tokens before the signature that
// references them, and the signature before any encryption that covers it.
func NewHeader(doc *xdm.Node, soapNS string, actor string, mustUnderstand bool) (*Header, error) {
	if soapNS != NSSOAP11 && soapNS != NSSOAP12 {
		return nil, fmt.Errorf("wss: unknown SOAP namespace %q", soapNS)
	}
	env := xmltree.DocumentElement(doc)
	if env == nil || !env.IsElement(soapNS, "Envelope") {
		return nil, errors.New("wss: document element is not a SOAP Envelope")
	}
	p := env.Name.Prefix

	var hdr *xdm.Node
	if kids := env.ChildElements(); len(kids) > 0 && kids[0].IsElement(soapNS, "Header") {
		hdr = kids[0]
	} else {
		hdr = xmltree.Element(env, p, soapNS, "Header")
		// AppendChild is the only way to link a node into the tree; move it
		// to the front, where the SOAP Header belongs.
		copy(env.Children[1:], env.Children[:len(env.Children)-1])
		env.Children[0] = hdr
	}

	actorAttr := "actor"
	if soapNS == NSSOAP12 {
		actorAttr = "role"
	}
	for _, e := range hdr.ChildElements() {
		if e.IsElement(NSWSSE, "Security") && xmltree.AttrValue(e, soapNS, actorAttr) == actor {
			return nil, fmt.Errorf("wss: a wsse:Security header for actor %q already exists", actor)
		}
	}

	// Built detached and attached last, so its own xmlns:wsse cannot
	// conflict with an ancestor's.
	sec := xmltree.Element(nil, "wsse", NSWSSE, "Security")
	if err := xmltree.Declare(sec, "wsse", NSWSSE); err != nil {
		return nil, err
	}
	if mustUnderstand {
		v := "1"
		if soapNS == NSSOAP12 {
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

// Append places an already-constructed element, such as a ds:Signature or
// an xenc:EncryptedKey, at the end of the security header.
func (h *Header) Append(el *xdm.Node) error {
	if el.Parent != nil {
		return errors.New("wss: element already has a parent")
	}
	h.el.AppendChild(el)
	return nil
}

// Element returns the wsse:Security element.
func (h *Header) Element() *xdm.Node { return h.el }
