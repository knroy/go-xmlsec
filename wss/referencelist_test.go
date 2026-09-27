package wss

import (
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
)

// SOAP Message Security 1.1.1 section 9.4.1, BSP R3231: one DataReference
// per EncryptedData of the step.
func TestNewReferenceList(t *testing.T) {
	list, err := NewReferenceList("ED-1", "EH-2")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := c14n.Bytes(list, c14n.Options{Algorithm: c14n.Exclusive10})
	want := `<xenc:ReferenceList xmlns:xenc="` + xmlsec.NSXEnc + `"><xenc:DataReference URI="#ED-1"></xenc:DataReference><xenc:DataReference URI="#EH-2"></xenc:DataReference></xenc:ReferenceList>`
	if string(got) != want || list.Parent != nil {
		t.Fatalf("got\n%s", got)
	}
	for name, ids := range map[string][]string{
		"none":       nil,
		"not NCName": {"a:b"},
		"empty":      {""},
		"twice":      {"a", "a"},
	} {
		if l, err := NewReferenceList(ids...); err == nil || l != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
