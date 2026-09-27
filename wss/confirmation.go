package wss

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// AddSignatureConfirmation adds a wsse11:SignatureConfirmation to a response
// header (SOAP Message Security 1.1.1 section 8.5), ahead of the existing
// content like AddBinarySecurityToken, and returns its wsu:Id, which it
// always carries (R5441). value is the octets of the ds:SignatureValue of a
// signature in the request, from SignatureValues, and becomes the Value
// attribute, base64; nil or empty means the request was not signed, and no
// Value is written.
//
// A responder adds one for every ds:Signature that was a direct child of the
// request's wsse:Security header, or exactly one without a value when there
// was none (section 8.5.1), and MUST include each in the response signature:
// sign it by its returned ID.
func (h *Header) AddSignatureConfirmation(value []byte) (string, error) {
	id, err := newID(h.doc)
	if err != nil {
		return "", err
	}
	// Built detached and attached last, as in AddBinarySecurityToken.
	sc := xmltree.Element(nil, "wsse11", xmlsec.NSWSSE11, "SignatureConfirmation")
	sc.AddNamespace("wsse11", xmlsec.NSWSSE11)
	sc.AddNamespace("wsu", xmlsec.NSWSU)
	xmltree.SetAttr(sc, "wsu", xmlsec.NSWSU, "Id", id)
	if len(value) > 0 {
		xmltree.SetAttr(sc, "", "", "Value", base64.StdEncoding.EncodeToString(value))
	}
	h.insert(h.front(), sc)
	return id, nil
}

// SignatureValues returns the octets of the ds:SignatureValue of each
// ds:Signature that is a direct child of security, a wsse:Security header,
// in document order: what a responder confirms, and what an initiator keeps
// to check the confirmations in the response. A signature that was
// encrypted is not seen until it is decrypted. A malformed signature, or a
// security that is not a wsse:Security element, is refused with
// xmlsec.ErrMalformed.
func SignatureValues(security *xdm.Node) ([][]byte, error) {
	if security == nil || !security.IsElement(xmlsec.NSWSSE, "Security") {
		return nil, fmt.Errorf("%w: not a wsse:Security header", xmlsec.ErrMalformed)
	}
	var out [][]byte
	for _, sig := range security.ChildElements() {
		if !sig.IsElement(xmlsec.NSDSig, "Signature") {
			continue
		}
		kids := sig.ChildElements()
		if len(kids) < 2 || !kids[1].IsElement(xmlsec.NSDSig, "SignatureValue") {
			return nil, fmt.Errorf("%w: ds:Signature without a ds:SignatureValue", xmlsec.ErrMalformed)
		}
		v, err := xmltree.Base64(kids[1])
		if err != nil || len(v) == 0 {
			return nil, fmt.Errorf("%w: ds:SignatureValue is not base64", xmlsec.ErrMalformed)
		}
		out = append(out, v)
	}
	return out, nil
}

// CheckSignatureConfirmations checks the wsse11:SignatureConfirmation
// children of security, the wsse:Security header of a response, against
// sent, the SignatureValues of the request it answers (SOAP Message Security
// 1.1.1 section 8.5.2). It refuses a response that:
//
//   - holds no SignatureConfirmation, or one without a wsu:Id (R5441);
//   - answers an unsigned request (sent empty) with anything but exactly one
//     SignatureConfirmation without a Value (section 8.5.1);
//   - answers a signed request with a SignatureConfirmation without a Value,
//     with an empty one, or with one that confirms no signature of the
//     request, or leaves a signature of the request unconfirmed; each
//     confirms exactly one.
//
// A mismatch is xmlsec.ErrSignatureInvalid, the wsse:FailedCheck fault;
// structure is xmlsec.ErrMalformed. Values are compared in constant time.
//
// A confirmation proves nothing unless the response signature covers it:
// check that the Coverage of dsig.Verify on the response includes every
// SignatureConfirmation.
func CheckSignatureConfirmations(security *xdm.Node, sent [][]byte) error {
	if security == nil || !security.IsElement(xmlsec.NSWSSE, "Security") {
		return fmt.Errorf("%w: not a wsse:Security header", xmlsec.ErrMalformed)
	}
	var confs []*xdm.Node
	for _, e := range security.ChildElements() {
		if e.IsElement(xmlsec.NSWSSE11, "SignatureConfirmation") {
			if e.Attr(xmlsec.NSWSU, "Id") == nil {
				return fmt.Errorf("%w: wsse11:SignatureConfirmation without a wsu:Id (BSP R5441)", xmlsec.ErrMalformed)
			}
			confs = append(confs, e)
		}
	}
	if len(confs) == 0 {
		return fmt.Errorf("%w: the response confirms no signature", xmlsec.ErrSignatureInvalid)
	}
	if len(sent) == 0 {
		if len(confs) != 1 || confs[0].Attr("", "Value") != nil {
			return fmt.Errorf("%w: an unsigned request is confirmed by one wsse11:SignatureConfirmation without a Value", xmlsec.ErrSignatureInvalid)
		}
		return nil
	}
	matched := make([]bool, len(sent))
	for _, c := range confs {
		a := c.Attr("", "Value")
		if a == nil {
			return fmt.Errorf("%w: a wsse11:SignatureConfirmation without a Value answers a signed request", xmlsec.ErrSignatureInvalid)
		}
		v, err := base64.StdEncoding.DecodeString(a.Value)
		if err != nil || len(v) == 0 {
			return fmt.Errorf("%w: wsse11:SignatureConfirmation Value is not base64", xmlsec.ErrMalformed)
		}
		// Every unmatched value is compared, so the time taken does not
		// show which one matched.
		hit := -1
		for i, s := range sent {
			if subtle.ConstantTimeCompare(v, s) == 1 && !matched[i] && hit < 0 {
				hit = i
			}
		}
		if hit < 0 {
			return fmt.Errorf("%w: a wsse11:SignatureConfirmation confirms no signature of the request", xmlsec.ErrSignatureInvalid)
		}
		matched[hit] = true
	}
	for _, m := range matched {
		if !m {
			return fmt.Errorf("%w: a signature of the request is not confirmed", xmlsec.ErrSignatureInvalid)
		}
	}
	return nil
}
