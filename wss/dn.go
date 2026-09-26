package wss

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"strings"
)

// An issuer name arrives as a string whose form each peer chooses: RFC 4514
// from Java, spaces after commas and quoted values from .NET, E= or
// EMAILADDRESS= or a dotted OID for the same attribute. sameIssuer compares
// one with a certificate's issuer as distinguished names instead.

// dnKeywords maps the attribute names peers write to their OIDs.
var dnKeywords = map[string]string{
	"CN": "2.5.4.3", "SN": "2.5.4.4", "SURNAME": "2.5.4.4", "SERIALNUMBER": "2.5.4.5",
	"C": "2.5.4.6", "L": "2.5.4.7", "ST": "2.5.4.8", "S": "2.5.4.8", "STREET": "2.5.4.9",
	"O": "2.5.4.10", "OU": "2.5.4.11", "T": "2.5.4.12", "TITLE": "2.5.4.12",
	"POSTALCODE": "2.5.4.17", "GIVENNAME": "2.5.4.42", "G": "2.5.4.42", "INITIALS": "2.5.4.43",
	"DNQ": "2.5.4.46", "DNQUALIFIER": "2.5.4.46", "ORGANIZATIONIDENTIFIER": "2.5.4.97",
	"DC": "0.9.2342.19200300.100.1.25", "UID": "0.9.2342.19200300.100.1.1",
	"E": "1.2.840.113549.1.9.1", "EMAILADDRESS": "1.2.840.113549.1.9.1",
}

// atv is one attribute of a name: its OID, dotted, and its value folded.
type atv struct{ oid, value string }

// fold makes a value comparable ignoring case and insignificant spaces, as
// LDAP's caseIgnoreMatch does.
func fold(v string) string { return strings.ToLower(strings.Join(strings.Fields(v), " ")) }

// sameIssuer reports whether the string s names the distinguished name
// whose DER is raw. Attribute values that are not strings never match.
func sameIssuer(s string, raw []byte) bool {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &seq); err != nil || len(rest) > 0 {
		return false
	}
	dn, ok := parseDN(s)
	if !ok || len(dn) != len(seq) {
		return false
	}
	for i, rdn := range seq {
		want := dn[len(dn)-1-i] // a string lists the RDNs last first
		if len(want) != len(rdn) {
			return false
		}
		for _, a := range rdn {
			v, isString := a.Value.(string)
			if !isString || !slices.Contains(want, atv{a.Type.String(), fold(v)}) {
				return false
			}
		}
	}
	return true
}

// parseDN parses an RFC 4514 distinguished name, also accepting the RFC 1779
// forms still in use: ';' between RDNs, spaces around separators, quoted
// values. It returns the RDNs in the string's order.
func parseDN(s string) ([][]atv, bool) {
	var dn [][]atv
	var rdn []atv
	for {
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			return nil, false
		}
		oid, ok := attrOID(strings.TrimSpace(s[:eq]))
		if !ok {
			return nil, false
		}
		v, rest, ok := dnValue(s[eq+1:])
		if !ok {
			return nil, false
		}
		rdn = append(rdn, atv{oid, fold(v)})
		if rest == "" {
			return append(dn, rdn), true
		}
		if rest[0] != '+' {
			dn, rdn = append(dn, rdn), nil
		}
		s = rest[1:]
	}
}

// attrOID returns the dotted OID an attribute name stands for.
func attrOID(t string) (string, bool) {
	u := strings.ToUpper(t)
	if oid, ok := dnKeywords[u]; ok {
		return oid, true
	}
	u = strings.TrimPrefix(u, "OID.")
	for p := range strings.SplitSeq(u, ".") {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return "", false
		}
	}
	return u, true
}

// dnValue reads one attribute value, returning it unescaped and the rest of
// the string from the separator that ends it (',', ';' or '+'), or "".
func dnValue(s string) (value, rest string, ok bool) {
	s = strings.TrimLeft(s, " ")
	if h, isHex := strings.CutPrefix(s, "#"); isHex {
		end := strings.IndexAny(h, ",;+")
		if end < 0 {
			end = len(h)
		}
		v, ok := derString(strings.TrimSpace(h[:end]))
		return v, h[end:], ok
	}
	quoted := strings.HasPrefix(s, `"`)
	if quoted {
		s = s[1:]
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			if x, err := hex.DecodeString(s[i+1 : min(i+3, len(s))]); err == nil {
				b = append(b, x[0])
				i += 2
			} else {
				b = append(b, s[i+1])
				i++
			}
		case c == '\\':
			return "", "", false
		case quoted && c == '"':
			rest := strings.TrimLeft(s[i+1:], " ")
			return string(b), rest, rest == "" || strings.IndexByte(",;+", rest[0]) >= 0
		case !quoted && strings.IndexByte(",;+", c) >= 0:
			return string(b), s[i:], true
		default:
			b = append(b, c)
		}
	}
	return string(b), "", !quoted
}

// derString decodes an RFC 4514 hex value: the DER of a string.
func derString(h string) (string, bool) {
	der, err := hex.DecodeString(h)
	if err != nil {
		return "", false
	}
	var v any
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) > 0 {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
