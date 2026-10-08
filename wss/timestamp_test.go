package wss

import (
	"errors"
	"testing"
	"time"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func TestAddTimestampWithoutExpiry(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("x", 3600))
	if _, err := h.AddTimestamp(now, 0); err != nil {
		t.Fatal(err)
	}
	ts := h.Element().ChildElements()[0]
	kids := ts.ChildElements()
	if len(kids) != 1 || kids[0].StringValue() != "2026-09-25T11:00:00.000Z" {
		t.Fatalf("%d children, Created %q", len(kids), kids[0].StringValue())
	}
}

// At most one timestamp per header (R3227), never a negative ttl, and the
// timestamp goes first whenever it is added.
func TestAddTimestampRules(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddTimestamp(time.Unix(0, 0), -time.Second); err == nil {
		t.Fatal("negative ttl accepted")
	}
	if _, err := h.AddBinarySecurityToken(testCert(t, "c"), nil, xmlsec.BSTValueTypeX509v3); err != nil {
		t.Fatal(err)
	}
	id, err := h.AddTimestamp(time.Unix(0, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first := h.Element().ChildElements()[0]; xmltree.AttrValue(first, xmlsec.NSWSU, "Id") != id {
		t.Fatalf("timestamp is not first: %v", childNames(h))
	}
	if _, err := h.AddTimestamp(time.Unix(0, 0), time.Minute); err == nil {
		t.Fatal("second timestamp accepted")
	}
	if n := len(h.Element().ChildElements()); n != 2 {
		t.Fatalf("%d children after the refusals", n)
	}
}

// What AddTimestamp writes, ParseTimestamp reads back.
func TestTimestampRoundTrip(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), xmlsec.NSSOAP11, "", false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 25, 12, 0, 0, 123456789, time.FixedZone("x", 3600))
	if _, err := h.AddTimestamp(now, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	ts, err := ParseTimestamp(h.Element().ChildElements()[0])
	if err != nil {
		t.Fatal(err)
	}
	created := now.Truncate(time.Millisecond)
	if !ts.Created.Equal(created) || !ts.Expires.Equal(created.Add(5*time.Minute)) {
		t.Fatalf("%+v", ts)
	}
	if ts.Created.Location() != time.UTC {
		t.Errorf("Created in %v", ts.Created.Location())
	}
}

func timestampEl(t *testing.T, inner string) string {
	t.Helper()
	return `<wsu:Timestamp xmlns:wsu="` + xmlsec.NSWSU + `">` + inner + `</wsu:Timestamp>`
}

func TestParseTimestamp(t *testing.T) {
	const c, e = "2026-09-25T12:00:00Z", "2026-09-25T12:05:00.5Z"
	created := func(v string) string { return `<wsu:Created>` + v + `</wsu:Created>` }
	expires := func(v string) string { return `<wsu:Expires>` + v + `</wsu:Expires>` }
	for _, ok := range []struct {
		name, doc string
		expires   bool
	}{
		{"Created only", timestampEl(t, created(c)), false},
		{"Created and Expires", timestampEl(t, created(c)+expires(e)), true},
		{"whitespace around values", timestampEl(t, created(" \n"+c+"\t")+expires(e)), true},
		// xs:dateTime admits a zero offset for UTC, and more digits than
		// the milliseconds R3220 and R3229 say SHOULD NOT be exceeded.
		{"zero offset", timestampEl(t, created("2026-09-25T12:00:00+00:00")), false},
		{"negative zero offset", timestampEl(t, created("2026-09-25T12:00:00-00:00")), false},
	} {
		ts, err := ParseTimestamp(xmltree.DocumentElement(parseDoc(t, ok.doc)))
		if err != nil {
			t.Errorf("%s: %v", ok.name, err)
			continue
		}
		if want, _ := time.Parse(time.RFC3339, c); !ts.Created.Equal(want) || ts.Expires.IsZero() == ok.expires {
			t.Errorf("%s: %+v", ok.name, ts)
		}
	}
	ts, err := ParseTimestamp(xmltree.DocumentElement(parseDoc(t, timestampEl(t, created("2026-09-25T12:00:00.123456789Z")))))
	if err != nil || ts.Created.Nanosecond() != 123456789 {
		t.Errorf("nanoseconds: %+v, %v", ts, err)
	}

	for _, bad := range []struct{ name, doc string }{
		{"not a timestamp", `<wsu:Created xmlns:wsu="` + xmlsec.NSWSU + `">` + c + `</wsu:Created>`},
		{"empty (R3203)", timestampEl(t, ``)},
		{"Expires only (R3203)", timestampEl(t, expires(e))},
		{"Expires first (R3221)", timestampEl(t, expires(e)+created(c))},
		{"two Created (R3203)", timestampEl(t, created(c)+created(c))},
		{"two Expires (R3224)", timestampEl(t, created(c)+expires(e)+expires(e))},
		{"other element (R3222)", timestampEl(t, created(c)+`<x/>`)},
		{"Created ValueType (R3225)", timestampEl(t, `<wsu:Created ValueType="urn:t">`+c+`</wsu:Created>`)},
		{"Expires ValueType (R3226)", timestampEl(t, created(c)+`<wsu:Expires ValueType="urn:t">`+e+`</wsu:Expires>`)},
		{"offset, not UTC (R3217)", timestampEl(t, created("2026-09-25T12:00:00+01:00"))},
		{"no timezone (R3217)", timestampEl(t, created("2026-09-25T12:00:00"))},
		{"bad Expires (R3223)", timestampEl(t, created(c)+expires("tomorrow"))},
		{"empty fraction", timestampEl(t, created("2026-09-25T12:00:00.Z"))},
		{"leap second (R3213)", timestampEl(t, created("2026-12-31T23:59:60Z"))},
		{"month 13", timestampEl(t, created("2026-13-01T00:00:00Z"))},
	} {
		el := xmltree.DocumentElement(parseDoc(t, bad.doc))
		if _, err := ParseTimestamp(el); !errors.Is(err, xmlsec.ErrMalformed) {
			t.Errorf("%s: %v", bad.name, err)
		}
	}
	if _, err := ParseTimestamp(nil); !errors.Is(err, xmlsec.ErrMalformed) {
		t.Errorf("nil: %v", err)
	}
}

func TestTimestampCheck(t *testing.T) {
	created := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ts := Timestamp{Created: created, Expires: created.Add(5 * time.Minute)}
	noExpiry := Timestamp{Created: created}
	at := func(d time.Duration) time.Time { return created.Add(d) }
	for _, c := range []struct {
		name          string
		ts            Timestamp
		now           time.Time
		skew, maxAge  time.Duration
		expired, fail bool
	}{
		{"fresh", ts, at(time.Minute), 0, 0, false, false},
		{"at creation", ts, at(0), 0, 0, false, false},
		{"created in the future", ts, at(-time.Second), 0, 0, true, false},
		{"future within skew", ts, at(-time.Second), time.Second, 0, false, false},
		{"at expiry", ts, at(5 * time.Minute), 0, 0, true, false},
		{"expired within skew", ts, at(5 * time.Minute), time.Second, 0, false, false},
		{"expired beyond skew", ts, at(5*time.Minute + time.Second), time.Second, 0, true, false},
		{"no Expires, no maxAge", noExpiry, at(1000 * time.Hour), 0, 0, false, false},
		{"within maxAge", noExpiry, at(time.Minute), 0, time.Minute, false, false},
		{"older than maxAge", noExpiry, at(time.Minute + 1), 0, time.Minute, true, false},
		{"maxAge plus skew", noExpiry, at(time.Minute + time.Second), time.Second, time.Minute, false, false},
		{"negative skew", ts, at(0), -1, 0, false, true},
		{"negative maxAge", ts, at(0), 0, -1, false, true},
	} {
		err := c.ts.Check(c.now, c.skew, c.maxAge)
		switch {
		case c.expired && !errors.Is(err, xmlsec.ErrMessageExpired):
			t.Errorf("%s: %v, want ErrMessageExpired", c.name, err)
		case c.fail && (err == nil || errors.Is(err, xmlsec.ErrMessageExpired)):
			t.Errorf("%s: %v, want an argument error", c.name, err)
		case !c.expired && !c.fail && err != nil:
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
