package wss

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"

// AddTimestamp adds a wsu:Timestamp with Created and, if ttl is non-zero,
// Expires, as the first child of the header, where a receiver can check it
// before any cryptographic work. The returned id is its wsu:Id.
//
// A header holds at most one timestamp (SOAP Message Security 1.1.1 section
// 10, Basic Security Profile R3227), so a second call is refused, as is a
// negative ttl. Times are UTC, in milliseconds (R3217, R3220).
func (h *Header) AddTimestamp(now time.Time, ttl time.Duration) (string, error) {
	return h.addTimestamp(now, ttl, "")
}

// AddTimestampWithID is AddTimestamp with the timestamp's wsu:Id supplied
// by the caller, as AssignIDWith supplies one: for a byte-reproducible
// header. id must be an NCName not already in use in the document.
func (h *Header) AddTimestampWithID(now time.Time, ttl time.Duration, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("%w: AddTimestampWithID needs an ID", xmlsec.ErrMalformed)
	}
	return h.addTimestamp(now, ttl, id)
}

func (h *Header) addTimestamp(now time.Time, ttl time.Duration, id string) (string, error) {
	if ttl < 0 {
		return "", fmt.Errorf("wss: negative timestamp ttl %v", ttl)
	}
	for _, e := range h.el.ChildElements() {
		if e.IsElement(xmlsec.NSWSU, "Timestamp") {
			return "", errors.New("wss: the header already has a wsu:Timestamp")
		}
	}
	id, err := idFor(h.doc, id)
	if err != nil {
		return "", err
	}
	// Built detached and attached last, as in AddBinarySecurityToken.
	ts := xmltree.Element(nil, "wsu", xmlsec.NSWSU, "Timestamp")
	ts.AddNamespace("wsu", xmlsec.NSWSU)
	xmltree.SetAttr(ts, "wsu", xmlsec.NSWSU, "Id", id)
	now = now.UTC()
	xmltree.Text(xmltree.Element(ts, "wsu", xmlsec.NSWSU, "Created"), now.Format(timestampLayout))
	if ttl != 0 {
		xmltree.Text(xmltree.Element(ts, "wsu", xmlsec.NSWSU, "Expires"), now.Add(ttl).Format(timestampLayout))
	}
	h.insert(0, ts)
	return id, nil
}

// Timestamp is a received wsu:Timestamp.
type Timestamp struct {
	Created time.Time
	Expires time.Time // zero when the timestamp has no wsu:Expires
}

// dateTimeUTC is an xs:dateTime in UTC with at most millisecond precision.
var dateTimeUTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$`)

// ParseTimestamp reads a wsu:Timestamp, refusing with xmlsec.ErrMalformed
// one that breaks the Basic Security Profile: it must hold exactly one
// wsu:Created, then at most one wsu:Expires, and nothing else (R3203,
// R3224, R3221, R3222); neither may carry a ValueType (R3225, R3226); each
// is an xs:dateTime in UTC, written with Z (R3217, R3223), seconds below 60
// (R3213, R3215) and at most three fractional digits (R3220, R3229).
//
// It checks structure only. Timestamp.Check decides freshness.
func ParseTimestamp(el *xdm.Node) (Timestamp, error) {
	var ts Timestamp
	if el == nil || !el.IsElement(xmlsec.NSWSU, "Timestamp") {
		return ts, fmt.Errorf("%w: not a wsu:Timestamp", xmlsec.ErrMalformed)
	}
	kids := el.ChildElements()
	if len(kids) == 0 || len(kids) > 2 || !kids[0].IsElement(xmlsec.NSWSU, "Created") ||
		len(kids) == 2 && !kids[1].IsElement(xmlsec.NSWSU, "Expires") {
		return ts, fmt.Errorf("%w: wsu:Timestamp must hold wsu:Created and at most a wsu:Expires after it", xmlsec.ErrMalformed)
	}
	var err error
	if ts.Created, err = timestampTime(kids[0]); err != nil {
		return ts, err
	}
	if len(kids) == 2 {
		if ts.Expires, err = timestampTime(kids[1]); err != nil {
			return ts, err
		}
	}
	return ts, nil
}

func timestampTime(e *xdm.Node) (time.Time, error) {
	if e.Attr("", "ValueType") != nil {
		return time.Time{}, fmt.Errorf("%w: wsu:%s has a ValueType", xmlsec.ErrMalformed, e.Name.Local)
	}
	s := strings.Trim(e.StringValue(), " \t\r\n")
	t, err := time.Parse(time.RFC3339, s)
	if !dateTimeUTC.MatchString(s) || err != nil {
		return time.Time{}, fmt.Errorf("%w: wsu:%s %q is not a UTC xs:dateTime in milliseconds", xmlsec.ErrMalformed, e.Name.Local, s)
	}
	return t, nil
}

// Check reports whether the timestamp is fresh at now, returning
// xmlsec.ErrMessageExpired, the wsse:MessageExpired fault, when it is not:
// it has expired, it was created in the future, or, if maxAge is non-zero,
// it was created more than maxAge ago. skew is the clock difference allowed
// between sender and receiver, applied to each comparison in the sender's
// favour. Negative durations are refused.
//
// SOAP Message Security 1.1.1 section 10 RECOMMENDS that a receiver discard
// an expired message and leaves the judgement of the sender's clock to it:
// skew is that judgement. A timestamp stops no replay unless it is signed;
// check that a signature's Coverage includes it.
func (ts Timestamp) Check(now time.Time, skew, maxAge time.Duration) error {
	if skew < 0 || maxAge < 0 {
		return fmt.Errorf("wss: negative skew %v or maxAge %v", skew, maxAge)
	}
	switch {
	case ts.Created.After(now.Add(skew)):
		return fmt.Errorf("%w: created %v, in the future", xmlsec.ErrMessageExpired, ts.Created)
	case !ts.Expires.IsZero() && !now.Add(-skew).Before(ts.Expires):
		return fmt.Errorf("%w: expired %v", xmlsec.ErrMessageExpired, ts.Expires)
	case maxAge > 0 && now.Sub(ts.Created) > maxAge+skew:
		return fmt.Errorf("%w: created %v, more than %v ago", xmlsec.ErrMessageExpired, ts.Created, maxAge)
	}
	return nil
}
