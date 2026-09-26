package wss

import (
	"testing"
	"time"
)

func TestAddTimestampWithoutExpiry(t *testing.T) {
	h, err := NewHeader(parseDoc(t, env11), NSSOAP11, "", false)
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
