package dsig

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/knroy/go-xml/xdm"
	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/certpath"
	"github.com/knroy/go-xmlsec/internal/xmltree"
)

// maxX509Certificates bounds the ds:X509Certificate elements one ds:KeyInfo
// may carry. Every one is parsed, and finding the leaf compares every pair;
// a real certificate path is a handful.
const maxX509Certificates = 16

// X509Descriptor is a ds:X509Data child that identifies a certificate
// without carrying it (XML-DSig 4.5.4), for SignOptions.X509Descriptors.
type X509Descriptor int

const (
	// X509IssuerSerial emits ds:X509IssuerSerial: the issuer's
	// distinguished name as an RFC 4514 string, and the serial number.
	X509IssuerSerial X509Descriptor = iota + 1

	// X509SKI emits ds:X509SKI, the certificate's subject key identifier.
	// A certificate without that extension is refused.
	X509SKI

	// X509SubjectName emits ds:X509SubjectName, the subject's
	// distinguished name as an RFC 4514 string.
	X509SubjectName

	// X509Digest emits dsig11:X509Digest, the SHA-256 digest of the
	// certificate's DER encoding.
	X509Digest
)

// X509Identifier is what ds:X509Data says about a certificate it does not
// carry, as VerifyOptions.ResolveX509 receives it. A field is zero when the
// corresponding element is absent.
type X509Identifier struct {
	// IssuerName and Serial are ds:X509IssuerSerial: the issuer's
	// distinguished name as the signer wrote it (RFC 4514 is recommended,
	// not guaranteed) and the serial number.
	IssuerName string
	Serial     *big.Int

	// SKI is the decoded ds:X509SKI: the subject key identifier.
	SKI []byte

	// SubjectName is ds:X509SubjectName as the signer wrote it.
	SubjectName string

	// Digest is the decoded dsig11:X509Digest, the digest of the
	// certificate's DER encoding under DigestAlgorithm, which the digest
	// allow-list has already accepted.
	Digest          []byte
	DigestAlgorithm string
}

// x509Data is what the ds:X509Data elements of one ds:KeyInfo hold. Each
// descriptor is an X509Identifier with that one field set.
type x509Data struct {
	certs []*x509.Certificate
	descs []X509Identifier
	crls  [][]byte

	// descErr is why a descriptor could not be read, such as an
	// X509Digest under an algorithm outside the allow-list. It matters only
	// where the descriptors are consulted.
	descErr error
}

// x509Key resolves the ds:X509Data elements of one ds:KeyInfo (XML-DSig
// 4.5.4). Their certificates, at most maxX509Certificates, must hold
// exactly one leaf, the one that issued none of the others: it is the
// signing certificate, and the others are reported as intermediates. Every
// descriptor beside them is ignored, as it selects nothing, unless
// VerifyOptions.StrictX509Data requires each to describe one of the
// certificates (xmlsec1 describes each certificate it carries). Without a
// certificate the descriptors, each kind
// at most once, go to VerifyOptions.ResolveX509, and must all describe what
// it returns. ds:X509CRL is reported, not checked, and children in other
// namespaces are ignored.
func (c *keyContext) x509Key(els []*xdm.Node) (resolvedKey, error) {
	d, err := c.readX509Data(els)
	if err != nil {
		return resolvedKey{}, err
	}
	form := KeyInfoX509Data
	var cert *x509.Certificate
	switch {
	case len(d.certs) > 0:
		if cert = certpath.Leaf(d.certs); cert == nil {
			return resolvedKey{}, fmt.Errorf("%w: ds:X509Data holds no single leaf certificate", xmlsec.ErrUnsupportedKeyInfo)
		}
		if !c.opts.StrictX509Data {
			break
		}
		if d.descErr != nil {
			return resolvedKey{}, d.descErr
		}
		for _, id := range d.descs {
			if !slices.ContainsFunc(d.certs, func(c *x509.Certificate) bool { return matchX509(c, id) == nil }) {
				return resolvedKey{}, matchX509(cert, id)
			}
		}
	case d.descErr != nil:
		return resolvedKey{}, d.descErr
	case len(d.descs) > 0 && c.opts.ResolveX509 != nil:
		id, err := identifier(d.descs)
		if err != nil {
			return resolvedKey{}, err
		}
		if cert, err = c.opts.ResolveX509(id); err != nil {
			return resolvedKey{}, fmt.Errorf("%w: ResolveX509: %w", xmlsec.ErrUnsupportedKeyInfo, err)
		}
		if cert == nil {
			return resolvedKey{}, fmt.Errorf("%w: ResolveX509 returned no certificate", xmlsec.ErrUnsupportedKeyInfo)
		}
		if err := matchX509(cert, id); err != nil {
			return resolvedKey{}, err
		}
		form = KeyInfoX509Descriptors
	default:
		return resolvedKey{}, fmt.Errorf("%w: no ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo)
	}
	r := resolvedKey{cert: cert, pub: cert.PublicKey, form: form, crls: d.crls}
	for _, x := range d.certs {
		if x != cert {
			r.intermediates = append(r.intermediates, x)
		}
	}
	return r, nil
}

// identifier merges descriptors into one, refusing a kind given twice: it
// would name two certificates, and one is looked up.
func identifier(descs []X509Identifier) (X509Identifier, error) {
	var id X509Identifier
	for _, d := range descs {
		switch {
		case d.SKI != nil && id.SKI == nil:
			id.SKI = d.SKI
		case d.Digest != nil && id.Digest == nil:
			id.Digest, id.DigestAlgorithm = d.Digest, d.DigestAlgorithm
		case d.SubjectName != "" && id.SubjectName == "":
			id.SubjectName = d.SubjectName
		case d.Serial != nil && id.Serial == nil:
			id.IssuerName, id.Serial = d.IssuerName, d.Serial
		default:
			return id, fmt.Errorf("%w: ds:X509Data without a certificate repeats a descriptor", xmlsec.ErrUnsupportedKeyInfo)
		}
	}
	return id, nil
}

// readX509Data reads ds:X509Data elements.
func (c *keyContext) readX509Data(els []*xdm.Node) (x509Data, error) {
	var d x509Data
	for _, x := range els {
		for _, e := range x.ChildElements() {
			local := e.Name.Local
			if e.Name.URI != xmlsec.NSDSig && e.Name.URI != xmlsec.NSDSig11 {
				continue // XML-DSig 4.5.4: external elements from other namespaces
			}
			var b []byte
			var err error
			switch {
			case e.IsElement(xmlsec.NSDSig, "X509Certificate"), e.IsElement(xmlsec.NSDSig, "X509CRL"), e.IsElement(xmlsec.NSDSig, "X509SKI"), e.IsElement(xmlsec.NSDSig11, "X509Digest"):
				if b, err = xmltree.Base64(e); err != nil || len(b) == 0 {
					return d, malformed("%s is not base64", local)
				}
			}
			var id X509Identifier
			switch {
			case e.IsElement(xmlsec.NSDSig, "X509Certificate"):
				if len(d.certs) == maxX509Certificates {
					return d, fmt.Errorf("%w: more than %d ds:X509Certificate", xmlsec.ErrUnsupportedKeyInfo, maxX509Certificates)
				}
				cert, err := x509.ParseCertificate(b)
				if err != nil {
					return d, fmt.Errorf("%w: ds:X509Certificate: %v", xmlsec.ErrMalformed, err)
				}
				d.certs = append(d.certs, cert)
				continue
			case e.IsElement(xmlsec.NSDSig, "X509CRL"):
				d.crls = append(d.crls, b)
				continue
			case e.IsElement(xmlsec.NSDSig, "X509SKI"):
				id.SKI = b
			case e.IsElement(xmlsec.NSDSig11, "X509Digest"):
				alg := xmltree.AttrValue(e, "", "Algorithm")
				if err := allowed("X509Digest", alg, c.opts.AllowedDigestAlgorithms, defaultDigest); err != nil {
					d.descErr = cmp.Or(d.descErr, fmt.Errorf("%w: %w", xmlsec.ErrUnsupportedKeyInfo, err))
					continue
				}
				if _, ok := digestHash(alg); !ok {
					d.descErr = cmp.Or(d.descErr, fmt.Errorf("%w: %w: X509Digest %q", xmlsec.ErrUnsupportedKeyInfo, xmlsec.ErrUnsupportedAlgorithm, alg))
					continue
				}
				id.Digest, id.DigestAlgorithm = b, alg
			case e.IsElement(xmlsec.NSDSig, "X509SubjectName"):
				if id.SubjectName = strings.TrimSpace(e.StringValue()); id.SubjectName == "" {
					return d, malformed("empty ds:X509SubjectName")
				}
			case e.IsElement(xmlsec.NSDSig, "X509IssuerSerial"):
				kids := e.ChildElements()
				if len(kids) != 2 || !kids[0].IsElement(xmlsec.NSDSig, "X509IssuerName") || !kids[1].IsElement(xmlsec.NSDSig, "X509SerialNumber") {
					return d, malformed("ds:X509IssuerSerial must hold ds:X509IssuerName, ds:X509SerialNumber")
				}
				serial, ok := new(big.Int).SetString(strings.TrimSpace(kids[1].StringValue()), 10)
				if !ok {
					return d, malformed("ds:X509SerialNumber is not an integer")
				}
				id.IssuerName, id.Serial = strings.TrimSpace(kids[0].StringValue()), serial
			default:
				return d, fmt.Errorf("%w: %s in ds:X509Data", xmlsec.ErrUnsupportedKeyInfo, local)
			}
			d.descs = append(d.descs, id)
		}
	}
	return d, nil
}

// matchX509 refuses a descriptor that does not describe cert (XML-DSig
// 4.5.4: they "MUST refer to the certificate or certificates containing the
// validation key").
func matchX509(cert *x509.Certificate, id X509Identifier) error {
	var bad string
	switch {
	case id.SubjectName != "" && !dnEqual(id.SubjectName, cert.RawSubject):
		bad = "ds:X509SubjectName"
	case id.Serial != nil && (id.Serial.Cmp(cert.SerialNumber) != 0 || !dnEqual(id.IssuerName, cert.RawIssuer)):
		bad = "ds:X509IssuerSerial"
	case id.SKI != nil && !bytes.Equal(id.SKI, cert.SubjectKeyId):
		bad = "ds:X509SKI"
	case id.Digest != nil:
		h, _ := digestHash(id.DigestAlgorithm) // readX509Data checked it
		d := h.New()
		d.Write(cert.Raw)
		if !bytes.Equal(id.Digest, d.Sum(nil)) {
			bad = "dsig11:X509Digest"
		}
	}
	if bad != "" {
		return fmt.Errorf("%w: %s does not describe the certificate", xmlsec.ErrUnsupportedKeyInfo, bad)
	}
	return nil
}

// dnAttributes maps the attribute type names of RFC 4514 section 3, and
// those RFC 2253 producers commonly add, to their OIDs.
var dnAttributes = map[string]string{
	"CN": "2.5.4.3", "SN": "2.5.4.4", "SURNAME": "2.5.4.4", "SERIALNUMBER": "2.5.4.5",
	"C": "2.5.4.6", "L": "2.5.4.7", "ST": "2.5.4.8", "S": "2.5.4.8", "STREET": "2.5.4.9",
	"O": "2.5.4.10", "OU": "2.5.4.11", "T": "2.5.4.12", "TITLE": "2.5.4.12",
	"POSTALCODE": "2.5.4.17", "GIVENNAME": "2.5.4.42", "G": "2.5.4.42", "INITIALS": "2.5.4.43",
	"DNQUALIFIER": "2.5.4.46", "DC": "0.9.2342.19200300.100.1.25", "UID": "0.9.2342.19200300.100.1.1",
	"E": "1.2.840.113549.1.9.1", "EMAILADDRESS": "1.2.840.113549.1.9.1",
}

// dnEqual reports whether s, a distinguished name string, names the DER
// Name raw: the same RDNs, each with the same attributes. RFC 4514 writes
// the last RDN first, producers differ (Go's pkix.Name.String moves
// attributes it has no name for), and the descriptor selects nothing, so
// order is not compared. Values compare with case and runs of whitespace
// folded, an approximation of caseIgnoreMatch.
func dnEqual(s string, raw []byte) bool {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		return false
	}
	var want []string
	for _, rdn := range rdns {
		var attrs []string
		for _, atv := range rdn {
			attrs = append(attrs, atv.Type.String()+"="+foldDN(fmt.Sprint(atv.Value)))
		}
		slices.Sort(attrs)
		want = append(want, strings.Join(attrs, "+"))
	}
	got, ok := parseDN(s)
	slices.Sort(got)
	slices.Sort(want)
	return ok && slices.Equal(got, want)
}

// foldDN folds case and whitespace runs, and trims.
func foldDN(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

// parseDN parses an RFC 4514 distinguished name string: RDNs separated by
// ',' (or ';', RFC 2253's alternative), attributes within one by '+', each
// "type=value" with a short name, a dotted OID or "OID." and one, and the
// value either escaped text or '#' and the hex of its BER encoding. Each
// RDN is returned as its sorted "oid=folded value" attributes joined by '+'.
func parseDN(s string) ([]string, bool) {
	var dn []string
	var rdn []string
	flush := func() {
		slices.Sort(rdn)
		dn, rdn = append(dn, strings.Join(rdn, "+")), nil
	}
	s = strings.TrimSpace(s)
	for {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return nil, false
		}
		oid, ok := dnAttributeOID(strings.TrimSpace(s[:eq]))
		if !ok {
			return nil, false
		}
		value, rest, ok := dnValue(strings.TrimLeft(s[eq+1:], " "))
		if !ok {
			return nil, false
		}
		rdn = append(rdn, oid+"="+value)
		if rest == "" {
			flush()
			return dn, true
		}
		if rest[0] != '+' {
			flush()
		}
		s = strings.TrimLeft(rest[1:], " ")
	}
}

// dnAttributeOID returns the dotted OID an attribute type names.
func dnAttributeOID(t string) (string, bool) {
	if oid, ok := dnAttributes[strings.ToUpper(t)]; ok {
		return oid, true
	}
	if len(t) > 4 && strings.EqualFold(t[:4], "OID.") {
		t = t[4:]
	}
	for part := range strings.SplitSeq(t, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return "", false
		}
	}
	return t, strings.Contains(t, ".")
}

// dnValue reads one attribute value, returning it folded and the rest of
// the string from the separator that ended it.
func dnValue(s string) (value, rest string, ok bool) {
	end := strings.IndexAny(s, ",+;")
	if strings.HasPrefix(s, "#") {
		if end < 0 {
			end = len(s)
		}
		b, err := hex.DecodeString(strings.TrimSpace(s[1:end]))
		var v any
		if err != nil {
			return "", "", false
		}
		if rest, err := asn1.Unmarshal(b, &v); err != nil || len(rest) > 0 {
			return "", "", false
		}
		return foldDN(fmt.Sprint(v)), s[end:], true
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == ',' || ch == '+' || ch == ';':
			return foldDN(string(out)), s[i:], true
		case ch != '\\':
			out = append(out, ch)
		case i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b, _ := hex.DecodeString(s[i+1 : i+3])
			out = append(out, b[0])
			i += 2
		case i+1 < len(s):
			out = append(out, s[i+1])
			i++
		default:
			return "", "", false
		}
	}
	return foldDN(string(out)), "", true
}

func isHex(c byte) bool { return strings.IndexByte("0123456789abcdefABCDEF", c) >= 0 }

// dnString renders a DER Name as an RFC 4514 string.
func dnString(raw []byte) string {
	var rdns pkix.RDNSequence
	_, _ = asn1.Unmarshal(raw, &rdns) // raw is from a parsed certificate
	return rdns.String()
}

// addX509Data appends ds:X509Data to ki: the requested descriptors of the
// signing certificate, then, unless descriptorsOnly, the certificate and
// opts.Chain.
func addX509Data(ki *xdm.Node, cert *x509.Certificate, opts SignOptions, descriptorsOnly bool) error {
	switch {
	case descriptorsOnly && len(opts.X509Descriptors) == 0:
		return errors.New("dsig: KeyInfoX509Descriptors needs SignOptions.X509Descriptors")
	case len(opts.Chain) >= maxX509Certificates:
		return fmt.Errorf("dsig: SignOptions.Chain holds %d certificates; at most %d with the signing one", len(opts.Chain), maxX509Certificates)
	case len(opts.Chain) > 0 && certpath.Leaf(append([]*x509.Certificate{cert}, opts.Chain...)) != cert:
		return errors.New("dsig: the signing certificate is not the one leaf of itself and SignOptions.Chain")
	}
	b64 := base64.StdEncoding.EncodeToString
	xd := xmltree.Element(ki, "ds", xmlsec.NSDSig, "X509Data")
	add := func(parent *xdm.Node, local, text string) {
		xmltree.Text(xmltree.Element(parent, "ds", xmlsec.NSDSig, local), text)
	}
	seen := map[X509Descriptor]bool{}
	for _, d := range opts.X509Descriptors {
		if seen[d] {
			return fmt.Errorf("dsig: X509Descriptor %d requested twice", d)
		}
		seen[d] = true
		switch d {
		case X509IssuerSerial:
			is := xmltree.Element(xd, "ds", xmlsec.NSDSig, "X509IssuerSerial")
			add(is, "X509IssuerName", dnString(cert.RawIssuer))
			add(is, "X509SerialNumber", cert.SerialNumber.String())
		case X509SKI:
			if len(cert.SubjectKeyId) == 0 {
				return errors.New("dsig: X509SKI requested, and the signing certificate has no subject key identifier")
			}
			add(xd, "X509SKI", b64(cert.SubjectKeyId))
		case X509SubjectName:
			add(xd, "X509SubjectName", dnString(cert.RawSubject))
		case X509Digest:
			e, err := dsig11Element(xd, "X509Digest")
			if err != nil {
				return err
			}
			xmltree.SetAttr(e, "", "", "Algorithm", xmlsec.DigestSHA256)
			sum := sha256.Sum256(cert.Raw)
			xmltree.Text(e, b64(sum[:]))
		default:
			return fmt.Errorf("dsig: unknown X509Descriptor %d", d)
		}
	}
	if !descriptorsOnly {
		for _, c := range append([]*x509.Certificate{cert}, opts.Chain...) {
			add(xd, "X509Certificate", b64(c.Raw))
		}
	}
	return nil
}
