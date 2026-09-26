package wss

import (
	"time"

	"github.com/knroy/go-xmlsec/internal/xmltree"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

// AddTimestamp appends a wsu:Timestamp with Created and, if ttl is
// non-zero, Expires. The returned id is its wsu:Id.
func (h *Header) AddTimestamp(now time.Time, ttl time.Duration) (string, error) {
	id, err := newID(h.doc)
	if err != nil {
		return "", err
	}
	// Built detached and attached last, as in AddBinarySecurityToken.
	ts := xmltree.Element(nil, "wsu", NSWSU, "Timestamp")
	if err := setWSUID(ts, id); err != nil {
		return "", err
	}
	now = now.UTC()
	xmltree.Text(xmltree.Element(ts, "wsu", NSWSU, "Created"), now.Format(timestampLayout))
	if ttl != 0 {
		xmltree.Text(xmltree.Element(ts, "wsu", NSWSU, "Expires"), now.Add(ttl).Format(timestampLayout))
	}
	h.el.AppendChild(ts)
	return id, nil
}
