package xenc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/swa"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptAttachment encrypts an attachment and returns the ciphertext plus
// an xenc:EncryptedData carrying an xenc:CipherReference back to it.
//
// transform becomes the EncryptedData Type, as the SwA profile specifies
// (section 5.5.2), and selects what is encrypted:
//
//   - xmlsec.TransformAttachmentContentOnly: the body alone.
//   - xmlsec.TransformAttachmentComplete: the body with the MIME headers the
//     profile lists (Content-Description, Content-Disposition, Content-ID,
//     Content-Location, Content-Type) that the attachment has, serialized as
//     a MIME part: "Name: value" and CRLF for each, in that order and
//     unfolded, then an empty line, then the body. The profile does not fix
//     a layout; this is the one WSS4J reads, and writes without the space.
//
// The caller replaces the attachment's MIME body with the ciphertext, sets
// its Content-Type to application/octet-stream and its
// Content-Transfer-Encoding to binary, and places the element in the
// security header. For Attachment-Complete the caller also removes the
// part's Content-Description, Content-Disposition and Content-Location,
// which are now inside the ciphertext, and keeps its Content-ID, which the
// CipherReference names. This split exists because this library does not
// own MIME.
//
// The CipherReference always carries xmlsec.TransformAttachmentCiphertext, and
// names the attachment by "cid:" and its ID percent-encoded per RFC 2392,
// as DecryptAttachment and AttachmentSet.Lookup decode it. The
// EncryptedData MimeType is the attachment's Content-Type, when it has one.
func EncryptAttachment(att *xmlsec.Attachment, sessionKey []byte, transform string, opts EncryptOptions) ([]byte, *xdm.Node, error) {
	if att == nil {
		return nil, nil, errors.New("xenc: no attachment")
	}
	plaintext := att.Body
	switch transform {
	case xmlsec.TransformAttachmentContentOnly:
	case xmlsec.TransformAttachmentComplete:
		sel, err := swa.Selected(att.MIMEHeaders)
		if err != nil {
			return nil, nil, err
		}
		var part []byte
		for _, name := range swa.Headers {
			if v, ok := sel[name]; ok {
				part = append(part, name+": "+v+"\r\n"...)
			}
		}
		plaintext = append(append(part, "\r\n"...), att.Body...)
	default:
		return nil, nil, fmt.Errorf("%w: attachment transform %q", xmlsec.ErrUnsupportedAlgorithm, transform)
	}
	ed, err := newEncryptedData(transform, opts)
	if err != nil {
		return nil, nil, err
	}
	if sessionKey, err = dataKey(ed, sessionKey, opts); err != nil {
		return nil, nil, err
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, plaintext)
	if err != nil {
		return nil, nil, err
	}
	if mt := contentType(att); mt != "" {
		xmltree.SetAttr(ed, "", "", "MimeType", mt)
	}
	cd := element(ed, "CipherData")
	place(ed)
	cr := element(cd, "CipherReference")
	xmltree.SetAttr(cr, "", "", "URI", "cid:"+cidEscape(att.ID))
	tr := nsElement(element(cr, "Transforms"), "ds", xmlsec.NSDSig, "Transform")
	xmltree.SetAttr(tr, "", "", "Algorithm", xmlsec.TransformAttachmentCiphertext)
	return ct, ed, nil
}

// cidEscape percent-encodes a Content-ID for a cid: URL (RFC 2392), the
// URI encoding XML Encryption shares with XML Signature (section 3.3.1).
// Everything but the unreserved characters of RFC 3986 and the "@" of the
// addr-spec is encoded, "+" included: WSS4J decodes cid: URIs as form data,
// where "+" means a space.
func cidEscape(id string) string {
	var b strings.Builder
	for _, c := range []byte(id) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', strings.IndexByte("-._~@", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// transforms returns the Algorithm of each ds:Transform in a
// CipherReference's xenc:Transforms, refusing XSLT and XPath with
// xmlsec.ErrTransformRefused.
func transforms(cr *xdm.Node) ([]string, error) {
	algs, _, err := cipherTransforms(cr, nil)
	return algs, err
}

// contentType returns the attachment's Content-Type header, matched
// case-insensitively.
func contentType(att *xmlsec.Attachment) string {
	for k, v := range att.MIMEHeaders {
		if strings.EqualFold(k, "Content-Type") && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// DecryptAttachment decrypts an attachment whose xenc:EncryptedData carries
// a CipherReference. ciphertext is the attachment's raw MIME body.
//
// It returns the attachment as it was before encryption, identified by the
// CipherReference's cid: URI. The CipherReference may carry no transform or
// exactly xmlsec.TransformAttachmentCiphertext; XSLT and XPath are
// xmlsec.ErrTransformRefused, any other transform
// xmlsec.ErrUnsupportedAlgorithm. What replaces what in the received MIME part
// depends on the EncryptedData Type (SwA profile section 5.5.3):
//
//   - Attachment-Content-Only: Body replaces the part's body, and
//     MIMEHeaders holds only the Content-Type, from the MimeType attribute,
//     when there is one.
//   - Attachment-Complete: Body replaces the body and MIMEHeaders the
//     part's headers of the same names. A decrypted header the profile does
//     not list, or one present twice, is refused.
func DecryptAttachment(el *xdm.Node, ciphertext []byte, sessionKey []byte, opts DecryptOptions) (*xmlsec.Attachment, error) {
	alg, err := dataAlgorithm(el, opts)
	if err != nil {
		return nil, err
	}
	typ := el.AttrValue("Type")
	if typ != xmlsec.TransformAttachmentContentOnly && typ != xmlsec.TransformAttachmentComplete {
		return nil, fmt.Errorf("%w: EncryptedData Type %q", xmlsec.ErrUnsupportedAlgorithm, typ)
	}
	cd, err := cipherData(el)
	if err != nil {
		return nil, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(xmlsec.NSXEnc, "CipherReference") ||
		!strings.HasPrefix(kids[0].AttrValue("URI"), "cid:") {
		return nil, malformed("xenc:CipherData must hold one cid: xenc:CipherReference")
	}
	id, err := url.PathUnescape(strings.TrimPrefix(kids[0].AttrValue("URI"), "cid:"))
	if err != nil {
		return nil, malformed("CipherReference URI: %v", err)
	}
	algs, err := transforms(kids[0])
	if err != nil {
		return nil, err
	}
	if len(algs) > 1 || len(algs) == 1 && algs[0] != xmlsec.TransformAttachmentCiphertext {
		return nil, unsupported("attachment CipherReference transforms %q: only %s is supported", algs, xmlsec.TransformAttachmentCiphertext)
	}
	pt, err := open(alg, sessionKey, ciphertext)
	if err != nil {
		return nil, err
	}
	att := &xmlsec.Attachment{ID: id, Body: pt}
	if typ == xmlsec.TransformAttachmentContentOnly {
		if mt := el.AttrValue("MimeType"); mt != "" {
			att.MIMEHeaders = map[string][]string{"Content-Type": {mt}}
		}
		return att, nil
	}

	r := bytes.NewReader(pt)
	br := bufio.NewReader(r)
	h, err := textproto.NewReader(br).ReadMIMEHeader()
	if err != nil {
		return nil, malformed("decrypted MIME headers: %v", err)
	}
	sel, err := swa.Selected(h)
	if err != nil {
		return nil, err
	}
	if len(sel) != len(h) {
		return nil, malformed("decrypted MIME headers include one the SwA profile does not list")
	}
	att.MIMEHeaders = make(map[string][]string, len(sel))
	for k, v := range sel {
		att.MIMEHeaders[k] = []string{v}
	}
	att.Body = pt[len(pt)-r.Len()-br.Buffered():]
	return att, nil
}
