package dsig_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
)

// Transform chains that end in octets: canonicalization then base64 is not
// possible over XML, but base64 over an attachment is, and #WithComments
// canonicalization renders as its plain form.
func TestTransformChains(t *testing.T) {
	key := newKey(t, rsaKey)
	atts := attachments(t, "aGVs\r\nbG8=")
	signed := covSignAndPlace(t, key, dsig.KeyInfoX509Data, atts, func(id string) []dsig.Reference {
		return []dsig.Reference{
			{URI: "#" + id, DigestAlgorithm: xmlsec.DigestSHA384,
				Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10WithComments)}}},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA512,
				Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformBase64}}},
			{URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256},
		}
	})
	doc := parse(t, signed)
	cov, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: atts})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov.SignedElementIDs) != 1 || !cov.CoversAttachments("att-1@example.com") {
		t.Fatalf("coverage %+v", cov)
	}

	// The base64 transform digests the decoded octets, so a change in
	// whitespace alone does not alter it, but the untransformed reference does.
	doc = parse(t, signed)
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{Attachments: attachments(t, "aGVsbG8=")}); !errors.Is(err, xmlsec.ErrDigestMismatch) {
		t.Fatalf("whitespace change: %v", err)
	}
	if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); !errors.Is(err, xmlsec.ErrAttachmentNotFound) {
		t.Fatalf("no attachments: %v", err)
	}
}

// Every #WithComments transform digests as its plain form, since a bare
// dereference has already dropped comments.
func TestWithCommentsTransforms(t *testing.T) {
	key := newKey(t, rsaKey)
	for _, alg := range []c14n.Algorithm{c14n.Inclusive10WithComments, c14n.Inclusive11WithComments, c14n.Exclusive10WithComments} {
		t.Run(string(alg), func(t *testing.T) {
			signed, err := dsig.SignEnveloped(parse(t, []byte(metadata)), key, dsig.SignOptions{
				SignatureAlgorithm:        xmlsec.SigRSASHA256,
				CanonicalizationAlgorithm: string(c14n.Inclusive10),
				References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{
					{Algorithm: xmlsec.TransformEnvelopedSignature}, {Algorithm: string(alg)},
				}}},
				KeyInfo: dsig.KeyInfoX509Data,
			})
			if err != nil {
				t.Fatal(err)
			}
			doc := parse(t, signed)
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); err != nil {
				t.Fatal(err)
			}
			// Comments are outside the digest.
			doc = parse(t, []byte(strings.Replace(string(signed), "<!-- comment -->", "<!-- other -->", 1)))
			if _, err := dsig.Verify(doc, findSignature(doc), dsig.VerifyOptions{}); err != nil {
				t.Fatalf("comment change: %v", err)
			}
		})
	}
}
