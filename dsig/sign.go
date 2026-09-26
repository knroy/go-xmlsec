package dsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/xmltree"
	"github.com/knroy/go-xmlsec/wss"
)

// SignOptions configures signature generation.
type SignOptions struct {
	// SignatureAlgorithm is a Sig* constant. Required.
	SignatureAlgorithm string

	// CanonicalizationAlgorithm canonicalizes ds:SignedInfo itself,
	// independent of the algorithms used inside references. Required.
	CanonicalizationAlgorithm string

	// References are signed in the order given, which is preserved on the
	// wire.
	References []Reference

	// KeyInfo selects how key material is described. Required.
	KeyInfo KeyInfoSpec

	// SecurityTokenID is the wsu:Id of the wsse:BinarySecurityToken, already
	// in doc, that a KeyInfoSecurityTokenReference points at. Required for
	// that form, ignored otherwise.
	SecurityTokenID string

	// SignatureID, if set, becomes the Id attribute of ds:Signature.
	SignatureID string

	// Attachments resolves cid: references. Required if any reference uses
	// a cid: URI.
	Attachments xmlsec.AttachmentSet
}

// Sign creates a ds:Signature over the references in opts and returns it
// detached, for the caller to place: inside wsse:Security for WS-Security.
// The document is not modified.
//
// The CanonicalizationAlgorithm must be exclusive. ds:SignedInfo is
// canonicalized here, before the caller places the signature, and only
// exclusive canonicalization is independent of where it ends up. Use
// SignEnveloped for inclusive canonicalization.
func Sign(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) (*xdm.Node, error) {
	if !c14n.Algorithm(opts.CanonicalizationAlgorithm).Exclusive() {
		return nil, fmt.Errorf("%w: Sign needs an exclusive SignedInfo canonicalization, got %q; use SignEnveloped",
			xmlsec.ErrUnsupportedAlgorithm, opts.CanonicalizationAlgorithm)
	}
	return sign(doc, key, opts, nil)
}

// SignEnveloped creates an enveloped signature, appended as the last child
// of the document element, and returns the signed document as octets. doc
// itself is left unmodified.
//
// Every reference with URI "" must carry an enveloped-signature transform
// followed by a canonicalization transform.
//
// The returned octets are the document as signed, in canonical form
// (Inclusive10WithComments, so comments survive). Callers transmit exactly
// these octets and never re-serialize the document.
func SignEnveloped(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) ([]byte, error) {
	el := xmltree.DocumentElement(doc)
	if el == nil {
		return nil, fmt.Errorf("%w: no document element", xmlsec.ErrMalformed)
	}
	n := len(el.Children)
	defer func() { el.Children = el.Children[:n] }()

	if _, err := sign(doc, key, opts, el); err != nil {
		return nil, err
	}
	return c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
}

// sign builds the signature, attaching it to parent first if non-nil so
// that references and ds:SignedInfo are processed in their final position.
func sign(doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions, parent *xdm.Node) (*xdm.Node, error) {
	sigHash, ok := xmlsec.SignatureHash(opts.SignatureAlgorithm)
	if !ok {
		return nil, fmt.Errorf("%w: signature %q", xmlsec.ErrUnsupportedAlgorithm, opts.SignatureAlgorithm)
	}
	if !isC14N(opts.CanonicalizationAlgorithm) {
		return nil, fmt.Errorf("%w: canonicalization %q", xmlsec.ErrUnsupportedAlgorithm, opts.CanonicalizationAlgorithm)
	}
	if len(opts.References) == 0 {
		return nil, errors.New("dsig: no references")
	}
	if key.Signer == nil || key.Certificate == nil {
		return nil, errors.New("dsig: KeyProvider needs Signer and Certificate")
	}
	if pub, ok := key.Signer.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Certificate.PublicKey) {
		return nil, errors.New("dsig: Signer does not match Certificate")
	}
	for _, r := range opts.References {
		if r.URI == "" && (len(r.Transforms) == 0 || r.Transforms[0].Algorithm != xmlsec.TransformEnvelopedSignature) {
			return nil, fmt.Errorf("%w: a reference to the whole document must begin with enveloped-signature", xmlsec.ErrMalformed)
		}
	}

	sig := xmltree.Element(parent, "ds", NSDSig, "Signature")
	if err := xmltree.Declare(sig, "ds", NSDSig); err != nil {
		return nil, err
	}
	if opts.SignatureID != "" {
		xmltree.SetAttr(sig, "", "", "Id", opts.SignatureID)
	}
	si := xmltree.Element(sig, "ds", NSDSig, "SignedInfo")
	algElement(si, "CanonicalizationMethod", opts.CanonicalizationAlgorithm)
	algElement(si, "SignatureMethod", opts.SignatureAlgorithm)

	for _, r := range opts.References {
		dh, ok := xmlsec.DigestHash(r.DigestAlgorithm)
		if !ok {
			return nil, fmt.Errorf("%w: digest %q", xmlsec.ErrUnsupportedAlgorithm, r.DigestAlgorithm)
		}
		h := dh.New()
		if _, err := digestReference(h, doc, sig, r.URI, r.Transforms, opts.Attachments); err != nil {
			return nil, err
		}
		ref := xmltree.Element(si, "ds", NSDSig, "Reference")
		if r.ID != "" {
			xmltree.SetAttr(ref, "", "", "Id", r.ID)
		}
		if r.Type != "" {
			xmltree.SetAttr(ref, "", "", "Type", r.Type)
		}
		xmltree.SetAttr(ref, "", "", "URI", r.URI)
		if len(r.Transforms) > 0 {
			ts := xmltree.Element(ref, "ds", NSDSig, "Transforms")
			for _, t := range r.Transforms {
				tr := algElement(ts, "Transform", t.Algorithm)
				if err := inclusiveNamespaces(tr, t); err != nil {
					return nil, err
				}
			}
		}
		algElement(ref, "DigestMethod", r.DigestAlgorithm)
		xmltree.Text(xmltree.Element(ref, "ds", NSDSig, "DigestValue"), base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}

	h := sigHash.New()
	if _, err := c14n.DigestNodeSet(h, c14n.Subtree(si), c14n.Options{Algorithm: c14n.Algorithm(opts.CanonicalizationAlgorithm)}); err != nil {
		return nil, err
	}
	value, err := signDigest(key.Signer, opts.SignatureAlgorithm, sigHash, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	xmltree.Text(xmltree.Element(sig, "ds", NSDSig, "SignatureValue"), base64.StdEncoding.EncodeToString(value))

	if err := addKeyInfo(sig, doc, key, opts); err != nil {
		return nil, err
	}
	return sig, nil
}

func algElement(parent *xdm.Node, local, alg string) *xdm.Node {
	e := xmltree.Element(parent, "ds", NSDSig, local)
	xmltree.SetAttr(e, "", "", "Algorithm", alg)
	return e
}

func inclusiveNamespaces(tr *xdm.Node, t TransformSpec) error {
	if !c14n.Algorithm(t.Algorithm).Exclusive() || len(t.InclusiveNamespacePrefixes) == 0 {
		return nil
	}
	in := xmltree.Element(tr, "ec", NSExcC14N, "InclusiveNamespaces")
	if err := xmltree.Declare(in, "ec", NSExcC14N); err != nil {
		return err
	}
	xmltree.SetAttr(in, "", "", "PrefixList", c14n.FormatPrefixList(t.InclusiveNamespacePrefixes))
	return nil
}

func addKeyInfo(sig, doc *xdm.Node, key xmlsec.KeyProvider, opts SignOptions) error {
	switch opts.KeyInfo {
	case KeyInfoNone:
		return nil
	case KeyInfoX509Data:
		ki := xmltree.Element(sig, "ds", NSDSig, "KeyInfo")
		xd := xmltree.Element(ki, "ds", NSDSig, "X509Data")
		xmltree.Text(xmltree.Element(xd, "ds", NSDSig, "X509Certificate"), base64.StdEncoding.EncodeToString(key.Certificate.Raw))
		return nil
	case KeyInfoSecurityTokenReference:
		tok, err := wss.FindByID(doc, opts.SecurityTokenID)
		if err != nil {
			return fmt.Errorf("dsig: SecurityTokenID: %w", err)
		}
		cert, err := wss.ParseBinarySecurityToken(tok)
		if err != nil {
			return err
		}
		if !cert.Equal(key.Certificate) {
			return errors.New("dsig: the referenced security token does not carry the signing certificate")
		}
		str, err := wss.NewSecurityTokenReference(doc, opts.SecurityTokenID, tok.AttrValue("ValueType"))
		if err != nil {
			return err
		}
		xmltree.Element(sig, "ds", NSDSig, "KeyInfo").AppendChild(str)
		return nil
	}
	return fmt.Errorf("dsig: unknown KeyInfoSpec %d", opts.KeyInfo)
}

// signDigest signs in the XML-DSig encoding: PKCS#1 v1.5 for RSA, and the
// fixed-width r||s concatenation, not ASN.1, for ECDSA.
func signDigest(s crypto.Signer, alg string, h crypto.Hash, digest []byte) ([]byte, error) {
	isEC := strings.Contains(alg, "#ecdsa-")
	switch pub := s.Public().(type) {
	case *rsa.PublicKey:
		if isEC {
			break
		}
		return s.Sign(rand.Reader, digest, h)
	case *ecdsa.PublicKey:
		if !isEC {
			break
		}
		der, err := s.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, err
		}
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("dsig: signer returned malformed ECDSA signature")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		rs.R.FillBytes(out[:size])
		rs.S.FillBytes(out[size:])
		return out, nil
	}
	return nil, fmt.Errorf("%w: %s with a %T key", xmlsec.ErrUnsupportedAlgorithm, alg, s.Public())
}
