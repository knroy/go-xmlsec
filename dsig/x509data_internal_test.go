package dsig

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// dnEqual compares an RFC 4514 string with a DER Name as xmlsec1, Santuario
// and Go write them: escapes, #hex values, OIDs, multi-valued RDNs, case,
// spacing and RDN order do not matter; anything unparsable never matches.
func TestDNEqual(t *testing.T) {
	email := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	name := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "NO"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Example Org"}, {Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "Unit"}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: `a,b+"c"`}},
		{{Type: email, Value: "x@example.com"}},
	}
	raw, err := asn1.Marshal(name)
	if err != nil {
		t.Fatal(err)
	}
	emailDER, _ := asn1.Marshal("x@example.com")
	emailHex := "#" + hexString(emailDER)
	cases := []struct {
		dn   string
		want bool
	}{
		{name.String(), true},
		{`1.2.840.113549.1.9.1=` + emailHex + `,CN=a\,b\+\"c\",O=Example Org+OU=Unit,C=NO`, true},
		{`C=NO; ou=unit + o=EXAMPLE   ORG; cn=a\2cb\2B\22c\22; EMAILADDRESS=x@example.com`, true},
		{`E=X@example.com,OID.2.5.4.3=a\,b\+"c",2.5.4.10=Example Org+OU=Unit,C=#1302` + hexString([]byte("NO")), true},
		{`E=x@example.com,CN=a\,b\+"c",O=Example Org,OU=Unit,C=NO`, false},
		{`E=x@example.com,CN=other,O=Example Org+OU=Unit,C=NO`, false},
		{`CN=a\,b\+"c",O=Example Org+OU=Unit,C=NO`, false},
		{`garbage`, false},
		{`X=1`, false},
		{`1..2=x`, false},
		{`OID.=x`, false},
		{`CN=#zz`, false},
		{`CN=#0c`, false},
		{`CN=#0c0161ff`, false},
		{`CN=a\`, false},
	}
	for _, c := range cases {
		if got := dnEqual(c.dn, raw); got != c.want {
			t.Errorf("%q: got %v", c.dn, got)
		}
	}
	if dnEqual(name.String(), []byte{0}) {
		t.Error("matched an invalid Name")
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&15])
	}
	return string(out)
}
