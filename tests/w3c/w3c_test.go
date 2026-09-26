package w3c

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// entry is one MANIFEST.json record.
type entry struct {
	Path      string `json:"path"`
	Source    string `json:"source"`
	Signature string `json:"signature"` // "enveloped": child of the document element; "root": the document element
	Expect    string `json:"expect"`    // "verify", "refuse" or "bug"
	Error     string `json:"error"`
	Reason    string `json:"reason"`
	Bug       string `json:"bug"`

	Coverage struct {
		WholeDocumentSigned bool     `json:"whole_document_signed"`
		SignedElementIDs    []string `json:"signed_element_ids"`
		KeyInfoForm         string   `json:"key_info_form"`
	} `json:"coverage"`

	Algorithms struct {
		Signature        string   `json:"signature"`
		Canonicalization string   `json:"canonicalization"`
		Digest           []string `json:"digest"`
		Transforms       []string `json:"transforms"`
	} `json:"algorithms"`
}

var sentinels = map[string]error{
	"ErrUnsupportedAlgorithm": xmlsec.ErrUnsupportedAlgorithm,
	"ErrAlgorithmNotAllowed":  xmlsec.ErrAlgorithmNotAllowed,
	"ErrTransformRefused":     xmlsec.ErrTransformRefused,
	"ErrUnverifiable":         xmlsec.ErrUnverifiable,
	"ErrMalformed":            xmlsec.ErrMalformed,
	"ErrDigestMismatch":       xmlsec.ErrDigestMismatch,
	"ErrSignatureInvalid":     xmlsec.ErrSignatureInvalid,
	"ErrLimitExceeded":        xmlsec.ErrLimitExceeded,
	"ErrAmbiguousID":          xmlsec.ErrAmbiguousID,
	"ErrIDNotFound":           xmlsec.ErrIDNotFound,
	"ErrUnsupportedKeyInfo":   xmlsec.ErrUnsupportedKeyInfo,
}

var keyInfoForms = map[string]dsig.KeyInfoSpec{
	"None":                   dsig.KeyInfoNone,
	"X509Data":               dsig.KeyInfoX509Data,
	"SecurityTokenReference": dsig.KeyInfoSecurityTokenReference,
	"KeyValue":               dsig.KeyInfoKeyValue,
	"DEREncodedKeyValue":     dsig.KeyInfoDEREncodedKeyValue,
}

func TestW3CInteropVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/MANIFEST.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []entry
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("empty manifest")
	}
	for _, e := range entries {
		t.Run(e.Path, func(t *testing.T) { check(t, e) })
	}
}

func check(t *testing.T, e entry) {
	if e.Expect == "bug" {
		t.Skip("suspected go-xmlsec bug: " + e.Bug)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(e.Path)))
	if err != nil {
		t.Fatal(err)
	}
	tree, err := xmlsec.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sig := locate(tree.Root, e.Signature)
	if sig == nil {
		t.Fatalf("no ds:Signature (%s)", e.Signature)
	}
	checkAlgorithms(t, e, sig)

	// The vectors are enveloping signatures over a ds:Object, identified by
	// the unqualified Id of the XML Signature schema itself.
	cov, err := dsig.Verify(tree.Root, sig, dsig.VerifyOptions{
		IDAttributes: []xdm.QName{dsig.IDAttrDSig},
	})
	switch e.Expect {
	case "verify":
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		want := e.Coverage
		if cov.WholeDocumentSigned != want.WholeDocumentSigned ||
			!slices.Equal(cov.SignedElementIDs, want.SignedElementIDs) && len(cov.SignedElementIDs)+len(want.SignedElementIDs) > 0 ||
			cov.KeyInfoForm != keyInfoForms[want.KeyInfoForm] || cov.PublicKey == nil {
			t.Errorf("coverage: whole=%v ids=%v form=%v, want %+v",
				cov.WholeDocumentSigned, cov.SignedElementIDs, cov.KeyInfoForm, want)
		}
		for _, r := range cov.References {
			if !slices.Contains(e.Algorithms.Digest, r.DigestAlgorithm) {
				t.Errorf("verified reference %q used digest %s, not in manifest", r.URI, r.DigestAlgorithm)
			}
		}
	case "refuse":
		s, ok := sentinels[e.Error]
		if !ok {
			t.Fatalf("manifest names unknown sentinel %q", e.Error)
		}
		if !errors.Is(err, s) {
			t.Fatalf("Verify: got %v, want %s (%s)", err, e.Error, e.Reason)
		}
	default:
		t.Fatalf("unknown expectation %q", e.Expect)
	}
}

// locate returns the ds:Signature the manifest describes: the document
// element itself, or the ds:Signature child of the document element.
func locate(doc *xdm.Node, where string) *xdm.Node {
	root := doc.ChildElements()[0]
	if where == "root" {
		if root.IsElement(dsig.NSDSig, "Signature") {
			return root
		}
		return nil
	}
	for _, c := range root.ChildElements() {
		if c.IsElement(dsig.NSDSig, "Signature") {
			return c
		}
	}
	return nil
}

// checkAlgorithms confirms the manifest's algorithm URIs are the ones the
// document's ds:SignedInfo actually declares.
func checkAlgorithms(t *testing.T, e entry, sig *xdm.Node) {
	t.Helper()
	si := sig.ChildElements()[0]
	var digest, transforms []string
	var walk func(*xdm.Node)
	walk = func(n *xdm.Node) {
		for _, c := range n.ChildElements() {
			switch {
			case c.IsElement(dsig.NSDSig, "DigestMethod"):
				if a := c.AttrValue("Algorithm"); !slices.Contains(digest, a) {
					digest = append(digest, a)
				}
			case c.IsElement(dsig.NSDSig, "Transform"):
				transforms = append(transforms, c.AttrValue("Algorithm"))
			}
			walk(c)
		}
	}
	walk(si)
	slices.Sort(digest)
	kids := si.ChildElements()
	a := e.Algorithms
	if kids[0].AttrValue("Algorithm") != a.Canonicalization || kids[1].AttrValue("Algorithm") != a.Signature ||
		!slices.Equal(digest, a.Digest) || !slices.Equal(transforms, a.Transforms) && len(transforms)+len(a.Transforms) > 0 {
		t.Errorf("algorithms in document: c14n=%s sig=%s digest=%v transforms=%v; manifest: %+v",
			kids[0].AttrValue("Algorithm"), kids[1].AttrValue("Algorithm"), digest, transforms, a)
	}
}
