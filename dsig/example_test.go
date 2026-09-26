package dsig_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/knroy/go-xml/c14n"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/dsig"
	"github.com/knroy/go-xmlsec/wss"
)

// exampleKey stands in for a key loaded from PEM, a PKCS#11 token or a
// cloud KMS: any crypto.Signer with its certificate.
func exampleKey() xmlsec.KeyProvider {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return xmlsec.KeyProvider{Signer: priv, Certificate: cert}
}

// Sign a whole document with an enveloped signature, then verify it as a
// receiver would. This is the example in the README.
func Example_enveloped() {
	key := exampleKey()

	// Sign.
	tree, err := xmlsec.Parse([]byte(`<Invoice><Total>100.00</Total></Invoice>`))
	if err != nil {
		log.Fatal(err)
	}
	signed, err := dsig.SignEnveloped(tree.Root, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{
			URI:             "", // the whole document
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms: []dsig.TransformSpec{
				{Algorithm: xmlsec.TransformEnvelopedSignature},
				{Algorithm: string(c14n.Exclusive10)},
			},
		}},
		KeyInfo: dsig.KeyInfoX509Data,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Verify the received octets.
	received, err := xmlsec.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	invoice := received.Root.ChildElements()[0]
	sig := invoice.ChildElements()[1] // the signature is appended last
	cov, err := dsig.Verify(received.Root, sig, dsig.VerifyOptions{
		Certificate:                       key.Certificate, // the sender's, known in advance
		AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
		AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
		AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("whole document signed:", cov.WholeDocumentSigned)
	// Output: whole document signed: true
}

// Sign a SOAP body inside a WS-Security header, then verify and check that
// the body is what the signature covers.
func Example_wsSecurity() {
	key := exampleKey()

	tree, err := xmlsec.Parse([]byte(`<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope">` +
		`<S:Body><Order>42</Order></S:Body></S:Envelope>`))
	if err != nil {
		log.Fatal(err)
	}
	doc := tree.Root
	body := doc.ChildElements()[0].ChildElements()[0]

	bodyID, err := wss.AssignID(doc, body)
	if err != nil {
		log.Fatal(err)
	}
	hdr, err := wss.NewHeader(doc, wss.NSSOAP12, "", true)
	if err != nil {
		log.Fatal(err)
	}
	tokenID, err := hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3)
	if err != nil {
		log.Fatal(err)
	}
	sig, err := dsig.Sign(doc, key, dsig.SignOptions{
		SignatureAlgorithm:        xmlsec.SigRSASHA256,
		CanonicalizationAlgorithm: string(c14n.Exclusive10),
		References: []dsig.Reference{{
			URI:             "#" + bodyID,
			DigestAlgorithm: xmlsec.DigestSHA256,
			Transforms:      []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}},
		}},
		KeyInfo:         dsig.KeyInfoSecurityTokenReference,
		SecurityTokenID: tokenID,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := hdr.Append(sig); err != nil {
		log.Fatal(err)
	}

	// A receiver checks the signature, then that it covers the body.
	cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{Certificate: key.Certificate})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("body signed:", cov.Covers(bodyID) && cov.SignedElements[0] == body)
	// Output: body signed: true
}
