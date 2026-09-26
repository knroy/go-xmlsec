package xenc

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// EncryptOctets encrypts arbitrary octets, such as an image or a non-XML
// document, into an xenc:EncryptedData (sections 2.1.4 and 4.3, step 2),
// with opts.DataAlgorithm, which must be AES-GCM.
//
// The EncryptedData carries opts.Type, MimeType and Encoding when set, so a
// recipient knows what the octets are; each is optional. Without
// opts.CipherReferenceURI the ciphertext is inline in an xenc:CipherValue,
// and the returned ciphertext is nil. With it, the EncryptedData holds an
// xenc:CipherReference to that URI, without transforms, and the ciphertext
// is returned for the caller to store where the URI points: this library
// writes nothing anywhere. The caller places the element, adding a
// ds:KeyInfo, such as a ds:KeyName, when the recipient needs one.
//
// DecryptData decrypts it, fetching an external CipherReference through
// DecryptOptions.ResolveURI.
func EncryptOctets(plaintext, sessionKey []byte, opts EncryptOptions) ([]byte, *xdm.Node, error) {
	uri := opts.CipherReferenceURI
	if uri != "" {
		if _, err := url.Parse(uri); err != nil || uri[0] == '#' {
			return nil, nil, fmt.Errorf("xenc: CipherReferenceURI %q must be a URI outside the document", uri)
		}
	}
	opts.CipherReferenceURI = ""
	ed, err := newEncryptedData(opts.Type, opts)
	if err != nil {
		return nil, nil, err
	}
	ct, err := seal(opts.DataAlgorithm, sessionKey, plaintext)
	if err != nil {
		return nil, nil, err
	}
	cd := element(ed, "CipherData")
	place(ed)
	if uri == "" {
		xmltree.Text(element(cd, "CipherValue"), base64.StdEncoding.EncodeToString(ct))
		return nil, ed, nil
	}
	xmltree.SetAttr(element(cd, "CipherReference"), "", "", "URI", uri)
	return ct, ed, nil
}
