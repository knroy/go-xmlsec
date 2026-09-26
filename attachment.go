package xmlsec

import (
	"fmt"
	"net/url"
	"strings"
)

// Attachment is one MIME part referenced by a cid: URI from a ds:Reference
// or an xenc:CipherReference.
//
// Body holds the exact octets as they appear on the wire, after any
// compression and before any decompression. Digests are computed over these
// bytes. Callers must not mutate Body after construction: this library does
// not copy it.
type Attachment struct {
	// ID is the Content-ID with angle brackets removed. The cid: URI for
	// this attachment is "cid:" + ID.
	ID string

	// MIMEHeaders are the part's headers as they appear on the wire, used
	// only by the Attachment-Complete transform.
	MIMEHeaders map[string][]string

	Body []byte
}

// AttachmentSet resolves cid: URIs to attachments.
type AttachmentSet interface {
	// Lookup returns the attachment for a cid: URI, which includes the
	// "cid:" scheme prefix. It returns ErrAttachmentNotFound if no
	// attachment matches.
	Lookup(cidURI string) (*Attachment, error)

	// All returns every attachment in the set, in wire order.
	All() []*Attachment
}

type attachmentSet struct {
	list []*Attachment
	byID map[string]*Attachment
}

// NewAttachmentSet returns an AttachmentSet over the given attachments.
// It returns ErrDuplicateAttachmentID if two attachments share an ID.
func NewAttachmentSet(atts ...*Attachment) (AttachmentSet, error) {
	s := &attachmentSet{list: atts, byID: make(map[string]*Attachment, len(atts))}
	for _, a := range atts {
		if a == nil {
			return nil, fmt.Errorf("%w: nil attachment", ErrMalformed)
		}
		if _, dup := s.byID[a.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateAttachmentID, a.ID)
		}
		s.byID[a.ID] = a
	}
	return s, nil
}

// Lookup strips the scheme and percent-decodes the URI per RFC 2392 before
// comparing it to attachment IDs.
func (s *attachmentSet) Lookup(cidURI string) (*Attachment, error) {
	rest, ok := strings.CutPrefix(cidURI, "cid:")
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a cid: URI", ErrAttachmentNotFound, cidURI)
	}
	id, err := url.PathUnescape(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrAttachmentNotFound, cidURI, err)
	}
	a, ok := s.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAttachmentNotFound, cidURI)
	}
	return a, nil
}

func (s *attachmentSet) All() []*Attachment { return s.list }
