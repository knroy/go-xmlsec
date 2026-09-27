package dsig

import (
	"errors"
	"fmt"
	"slices"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// BuildManifest returns a ds:Manifest (XML-DSig 5.1) holding a digested
// ds:Reference for each of refs, not attached to any document. Its Id is
// opts.ManifestID. The references are checked and digested as Sign's are,
// with opts.IDAttributes, Attachments, ResolveURI, BaseURI and
// OmittedURIData; the other options are not used.
//
// A Manifest is signed by placing it in a ds:Object of SignOptions.Objects
// and referencing it: Reference{URI: "#" + opts.ManifestID, Type:
// xmlsec.TypeManifest}. Build it only once the references' targets stand
// as they will be verified: until it is placed, the enveloped-signature
// transform of one of its references removes nothing, and a same-document
// reference cannot name the signature's other ds:Object elements.
//
// Unlike a ds:SignedInfo reference, a failed ds:Manifest reference does not
// invalidate the signature: the verifier checks the references with
// VerifyManifest, which needs the Manifest itself to be signed.
func BuildManifest(doc *xdm.Node, refs []Reference, opts SignOptions) (*xdm.Node, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: BuildManifest needs a document", xmlsec.ErrMalformed)
	}
	if len(refs) == 0 {
		return nil, errors.New("dsig: no references")
	}
	if err := checkReferences(refs, opts, false); err != nil {
		return nil, err
	}
	if err := checkIDs(map[string]string{"ManifestID": opts.ManifestID}, signatureIDs(SignOptions{}, refs)); err != nil {
		return nil, err
	}
	m := xmltree.Element(nil, "ds", xmlsec.NSDSig, "Manifest")
	m.AddNamespace("ds", xmlsec.NSDSig)
	setOptional(m, "Id", opts.ManifestID)
	if err := addReferences(m, doc, m, refs, opts); err != nil {
		return nil, err
	}
	return m, nil
}

// VerifyManifest validates the references of a ds:Manifest (XML-DSig
// 5.1), which cov, returned by Verify for a signature over doc, must cover:
// the Manifest itself, or the ds:Object holding it, must be one of
// cov.SignedElements. Otherwise it is refused with
// xmlsec.ErrSignatureInvalid before any reference is processed: an unsigned
// Manifest proves nothing.
//
// Its references are checked exactly as Verify checks a signature's, with
// opts: the allow-lists and transform opt-ins before any digest,
// MaxReferences, at most one omitted URI through ResolveOmittedURI, and
// Attachments, IDAttributes, ResolveURI, BaseURI and RequireNFC. The key
// options are not used. Every reference must validate; the first that does
// not is returned as the error, ErrDigestMismatch for a changed target.
//
// The returned Coverage describes the Manifest's references alone, as
// Verify's does a signature's, and must be inspected in the same way. Its
// key fields are cov's. VerifiedReference.Raw is each ds:Reference under
// Exclusive C14N. The enveloped-signature transform removes the ds:Signature
// holding the Manifest, or when there is none, the Manifest. A document
// with no canonical form is reported as by Verify, with
// xmlsec.ErrUnverifiable.
func VerifyManifest(doc, manifest *xdm.Node, cov *Coverage, opts VerifyOptions) (*Coverage, error) {
	out, err := verifyManifest(doc, manifest, cov, opts)
	return out, unverifiable(err)
}

func verifyManifest(doc, manifest *xdm.Node, cov *Coverage, opts VerifyOptions) (*Coverage, error) {
	if doc == nil || manifest == nil || !manifest.IsElement(xmlsec.NSDSig, "Manifest") {
		return nil, malformed("not a ds:Manifest")
	}
	if manifest.Root() != doc.Root() {
		return nil, errors.New("dsig: manifest is not inside the document")
	}
	if cov == nil || !slices.ContainsFunc(cov.SignedElements, func(e *xdm.Node) bool {
		return e == manifest || e == manifest.Parent && e.IsElement(xmlsec.NSDSig, "Object")
	}) {
		return nil, fmt.Errorf("%w: the ds:Manifest is not covered by the signature", xmlsec.ErrSignatureInvalid)
	}
	if err := checkBaseURI(opts.BaseURI); err != nil {
		return nil, err
	}
	kids := manifest.ChildElements()
	if len(kids) == 0 {
		return nil, malformed("ds:Manifest must hold Reference+")
	}
	if limit := maxReferences(opts); len(kids) > limit {
		return nil, fmt.Errorf("%w: %d references, limit %d", xmlsec.ErrLimitExceeded, len(kids), limit)
	}
	refs := make([]parsedReference, len(kids))
	raw := make([][]byte, len(kids))
	for i, k := range kids {
		var err error
		if refs[i], err = parseReference(k); err != nil {
			return nil, err
		}
		if raw[i], err = c14n.Bytes(k, c14n.Options{Algorithm: c14n.Exclusive10}); err != nil {
			return nil, err
		}
	}
	if err := checkOmitted(refs, opts); err != nil {
		return nil, err
	}
	if err := admitReferences(refs, opts); err != nil {
		return nil, err
	}
	sig := manifest
	for a := manifest.Parent; a != nil; a = a.Parent {
		if a.IsElement(xmlsec.NSDSig, "Signature") {
			sig = a
			break
		}
	}
	out := &Coverage{Certificate: cov.Certificate, PublicKey: cov.PublicKey, KeyInfoForm: cov.KeyInfoForm}
	if err := digestReferences(out, doc, sig, refs, raw, opts); err != nil {
		return nil, err
	}
	return out, nil
}
