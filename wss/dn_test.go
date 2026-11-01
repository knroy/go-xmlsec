package wss

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

func rawName(t *testing.T, rdns ...pkix.RelativeDistinguishedNameSET) []byte {
	t.Helper()
	b, err := asn1.Marshal(pkix.RDNSequence(rdns))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSameIssuer(t *testing.T) {
	type a = pkix.AttributeTypeAndValue
	oid := func(s ...int) asn1.ObjectIdentifier { return s }
	cn, o, c := oid(2, 5, 4, 3), oid(2, 5, 4, 10), oid(2, 5, 4, 6)
	email, uid := oid(1, 2, 840, 113549, 1, 9, 1), oid(0, 9, 2342, 19200300, 100, 1, 1)
	// DER order C, O, then a two-valued RDN of CN and UID, then an email.
	raw := rawName(t,
		pkix.RelativeDistinguishedNameSET{a{Type: c, Value: "NO"}},
		pkix.RelativeDistinguishedNameSET{a{Type: o, Value: "Acme, Inc."}},
		pkix.RelativeDistinguishedNameSET{a{Type: cn, Value: "Test  CA"}, a{Type: uid, Value: "u1"}},
		pkix.RelativeDistinguishedNameSET{a{Type: email, Value: "ca@example.com"}},
	)
	for _, s := range []string{
		`E=ca@example.com,CN=Test  CA+UID=u1,O=Acme\, Inc.,C=NO`,
		`EMAILADDRESS=ca@example.com, UID=u1 + CN=test ca, O="Acme, Inc.", C=no`,
		`1.2.840.113549.1.9.1=#160e6361406578616d706c652e636f6d;oid.2.5.4.3=Test CA+0.9.2342.19200300.100.1.1=u1;O=Acme\2c Inc.;C=NO`,
		`  e = ca@example.com , cn=TEST CA+uid=U1 ,o = Acme\, Inc.  ,c=NO  `,
	} {
		if !sameIssuer(s, raw) {
			t.Errorf("%q does not match", s)
		}
	}
	for _, s := range []string{
		``,
		`E=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.`,         // an RDN short
		`E=ca@example.com,CN=Test CA,O=Acme\, Inc.,C=NO`,           // an attribute short
		`E=ca@example.com,CN=Test CA+UID=u2,O=Acme\, Inc.,C=NO`,    // a value differs
		`C=NO,O=Acme\, Inc.,CN=Test CA+UID=u1,E=ca@example.com`,    // DER order, not string order
		`E=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO,`,   // trailing separator
		`E=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C`,       // no '='
		`X=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`,    // unknown keyword
		`1..2=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`, // bad OID
		`E=#zz,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`,               // bad hex
		`E=#020101,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`,           // DER not a string
		`E=#16016100,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`,         // DER with trailing bytes
		`E=#1601,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO`,             // truncated DER
		`E=ca@example.com,CN=Test CA+UID=u1,O="Acme, Inc." x,C=NO`, // text after a quoted value
		`E=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C="NO`,   // unterminated quote
		`E=ca@example.com,CN=Test CA+UID=u1,O=Acme\, Inc.,C=NO\`,   // trailing backslash
	} {
		if sameIssuer(s, raw) {
			t.Errorf("%q matches", s)
		}
	}

	// A value that is not a string never matches, and neither does a name
	// that is not DER.
	intName := rawName(t, pkix.RelativeDistinguishedNameSET{a{Type: cn, Value: 1}})
	if sameIssuer(`CN=1`, intName) || sameIssuer(`CN=#020101`, intName) {
		t.Error("non-string value matched")
	}
	if sameIssuer(`CN=a`, []byte{0x30}) || sameIssuer(`CN=a`, append(rawName(t), 0)) {
		t.Error("malformed DER matched")
	}
}

func TestDNValueEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`a\,b`:        "a,b",
		`\41\42`:      "AB",
		`\c3\a6`:      "æ",
		`a\ `:         "a ",
		`\"q\"`:       `"q"`,
		`"a,b;c+d"  `: "a,b;c+d",
		`"a\"b"`:      `a"b`,
		`x\4`:         "x4", // a lone hex digit is a literal
	} {
		v, rest, ok := dnValue(in)
		if !ok || v != want || rest != "" {
			t.Errorf("%q: %q, %q, %v; want %q", in, v, rest, ok, want)
		}
	}
}

// foldJoin and dnValueAppend are fold and dnValue as they were.
func foldJoin(v string) string { return strings.ToLower(strings.Join(strings.Fields(v), " ")) }

func dnValueAppend(s string) (value, rest string, ok bool) {
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

// fold and dnValue give what they gave before they were made one pass,
// over edge cases and random strings of the characters that matter.
func TestFoldAndDNValueUnchanged(t *testing.T) {
	pieces := []string{"a", "Z", " ", "  ", "\t", "\n", "\u0085", "\u00a0", "\u2028", "\xff", "\xc3", "É", "İ", "Ⱥ", "ß",
		`\`, `"`, ",", ";", "+", "#", "4", "1", "c", "zz", `\41`, `\c3\a6`, `\,`, `\ `, "=", "#1601"}
	cases := []string{"", " ", "\t\n", `"`, `""`, `\`, `"a\"b"`, `x\4`, `\4g`, ` "a" ,b`, `"a" x`, `#160161`, `#zz,b`}
	r := rand.New(rand.NewPCG(3, 4))
	for range 20000 {
		var b strings.Builder
		for range r.IntN(12) {
			b.WriteString(pieces[r.IntN(len(pieces))])
		}
		cases = append(cases, b.String())
	}
	for _, s := range cases {
		if got, want := fold(s), foldJoin(s); got != want {
			t.Fatalf("fold(%q) = %q, want %q", s, got, want)
		}
		v, rest, ok := dnValue(s)
		wv, wrest, wok := dnValueAppend(s)
		if ok != wok || ok && (v != wv || rest != wrest) {
			t.Fatalf("dnValue(%q) = %q, %q, %v; want %q, %q, %v", s, v, rest, ok, wv, wrest, wok)
		}
	}
}
