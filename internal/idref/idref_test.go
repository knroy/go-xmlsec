package idref_test

import (
	"errors"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/idref"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

func TestFind(t *testing.T) {
	tree, err := xmlsec.Parse([]byte(`<r xmlns:wsu="` + idref.NSWSU + `">` +
		`<a wsu:Id="w"/><b xml:id="x"/><c Id="i"/><d Id="dup"/><e xml:id="dup"/><f Id="u"/></r>`))
	if err != nil {
		t.Fatal(err)
	}
	kids := xmltree.DocumentElement(tree.Root).ChildElements()
	id := xdm.QName{Local: "Id"}
	for _, c := range []struct {
		id    string
		extra []xdm.QName
		want  *xdm.Node
		err   error
	}{
		{"w", nil, kids[0], nil},
		{"x", nil, kids[1], nil},
		{"i", []xdm.QName{id}, kids[2], nil},
		{"i", nil, nil, xmlsec.ErrIDNotFound},
		{"dup", []xdm.QName{id}, nil, xmlsec.ErrAmbiguousID},
		{"dup", nil, kids[4], nil},
	} {
		// Resolution starts from any node of the document.
		got, err := idref.Find(kids[5], c.id, c.extra...)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s %v: got %v, %v", c.id, c.extra, got, err)
		}
	}
}
