package xenc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptAttachment encrypts an attachment body and returns the ciphertext
// plus an xenc:EncryptedData carrying an xenc:CipherReference back to it.
//
// The caller replaces the attachment's MIME body with the ciphertext, sets
// its Content-Type to application/octet-stream and its
// Content-Transfer-Encoding to binary, and places the element in the
// security header. This split exists because this library does not own MIME.
//
// transform is xmlsec.TransformAttachmentContentOnly and becomes the
// EncryptedData Type, as the SwA profile specifies; the CipherReference
// always carries TransformAttachmentCiphertext. Attachment-Complete is not
// yet supported.
func EncryptAttachment(att *xmlsec.Attachment, sessionKey []byte, transform string, opts EncryptOptions) ([]byte, *xdm.Node, error) {
	if att == nil {
		return nil, nil, errors.New("xenc: no attachment")
	}
	if transform != xmlsec.TransformAttachmentContentOnly {
		return nil, nil, fmt.Errorf("%w: attachment transform %q", xmlsec.ErrUnsupportedAlgorithm, transform)
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, att.Body)
	if err != nil {
		return nil, nil, err
	}

	ed := newRoot("EncryptedData")
	if mt := contentType(att); mt != "" {
		xmltree.SetAttr(ed, "", "", "MimeType", mt)
	}
	xmltree.SetAttr(ed, "", "", "Type", transform)
	setDataID(ed, opts)
	encryptionMethod(ed, opts.DataAlgorithm)
	cr := element(element(ed, "CipherData"), "CipherReference")
	xmltree.SetAttr(cr, "", "", "URI", "cid:"+att.ID)
	tr := xmltree.Element(element(cr, "Transforms"), "ds", NSDSig, "Transform")
	tr.AddNamespace("ds", NSDSig)
	xmltree.SetAttr(tr, "", "", "Algorithm", TransformAttachmentCiphertext)
	return ct, ed, nil
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
func DecryptAttachment(el *xdm.Node, ciphertext []byte, sessionKey []byte, allowedData []string) ([]byte, error) {
	alg, err := dataAlgorithm(el, allowedData)
	if err != nil {
		return nil, err
	}
	if t := el.AttrValue("Type"); t != xmlsec.TransformAttachmentContentOnly {
		return nil, fmt.Errorf("%w: EncryptedData Type %q", xmlsec.ErrUnsupportedAlgorithm, t)
	}
	cd, err := cipherData(el)
	if err != nil {
		return nil, err
	}
	kids := cd.ChildElements()
	if len(kids) != 1 || !kids[0].IsElement(NSXEnc, "CipherReference") ||
		!strings.HasPrefix(kids[0].AttrValue("URI"), "cid:") {
		return nil, malformed("xenc:CipherData must hold one cid: xenc:CipherReference")
	}
	return open(alg, sessionKey, ciphertext)
}
