//go:build interop

package interop

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// externalURI is never fetched: each side serves it from a local copy, the
// harness through a Santuario ResourceResolver, we through a URIResolver.
const externalURI = "http://example.invalid/resource.xml"

// externalResource is XML in a non-canonical serialization, so that the
// canonicalization case parses and reserializes it.
const externalResource = `<doc xmlns="urn:example"><a  b='1'></a><c>text</c></doc>`

// externalTransforms are the two octet paths: digested as they are, and
// parsed then canonicalized (XML-DSig 4.4.3.2).
var externalTransforms = map[string]string{"octets": "", "exclusive c14n": string(c14n.Exclusive10)}

func serveExternal(uri string) ([]byte, error) {
	if uri != externalURI {
		return nil, errors.New("not served")
	}
	return []byte(externalResource), nil
}

// We verify Santuario's signature over an external http: reference.
func TestWeVerifySantuarioExternalReference(t *testing.T) {
	for name, transform := range externalTransforms {
		t.Run(name, func(t *testing.T) {
			kp := newKeypair(t, rsaKey(t))
			out := filepath.Join(t.TempDir(), "out.xml")
			mustSantuario(t, "sign-external", tempFile(t, "in.xml", []byte(`<r/>`)), kp.keyPEM, kp.certPEM, out,
				externalURI, tempFile(t, "resource.xml", []byte(externalResource)), transform)
			signed := readFile(t, out)
			doc := parse(t, signed)
			cov, err := dsig.Verify(doc, find(doc, xmlsec.NSDSig, "Signature"), dsig.VerifyOptions{
				Certificate: kp.provider.Certificate, ResolveURI: serveExternal,
			})
			if err != nil {
				t.Fatalf("%v\n%s", err, signed)
			}
			if !slices.Equal(cov.ExternalURIs, []string{externalURI}) {
				t.Fatalf("coverage %+v", cov)
			}
		})
	}
}

// Santuario verifies our signature over an external http: reference, and
// refuses it when served other octets.
func TestSantuarioVerifiesOurExternalReference(t *testing.T) {
	for name, transform := range externalTransforms {
		t.Run(name, func(t *testing.T) {
			kp := newKeypair(t, rsaKey(t))
			doc := parse(t, []byte(`<r/>`))
			ref := dsig.Reference{URI: externalURI, DigestAlgorithm: xmlsec.DigestSHA256}
			if transform != "" {
				ref.Transforms = []dsig.TransformSpec{{Algorithm: transform}}
			}
			if _, err := dsig.Sign(doc, kp.provider, dsig.SignOptions{
				SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10),
				References: []dsig.Reference{ref}, KeyInfo: dsig.KeyInfoX509Data,
				Parent: xmltree.DocumentElement(doc), ResolveURI: serveExternal,
			}); err != nil {
				t.Fatal(err)
			}
			signed, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
			if err != nil {
				t.Fatal(err)
			}
			path := tempFile(t, "signed.xml", signed)
			mustSantuario(t, "verify-external", path, kp.certPEM, externalURI, tempFile(t, "resource.xml", []byte(externalResource)))
			if out, err := santuario(t, "verify-external", path, kp.certPEM, externalURI,
				tempFile(t, "other.xml", []byte(`<doc xmlns="urn:example"><a b="2"/></doc>`))); err == nil {
				t.Fatalf("Santuario accepted other octets:\n%s", out)
			}
		})
	}
}
