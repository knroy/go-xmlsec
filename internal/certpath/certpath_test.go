package certpath

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func cert(subject, issuer string, ski, aki []byte) *x509.Certificate {
	return &x509.Certificate{
		RawSubject: []byte(subject), RawIssuer: []byte(issuer),
		Subject: pkix.Name{CommonName: subject}, SubjectKeyId: ski, AuthorityKeyId: aki,
	}
}

func TestCertpathLeaf(t *testing.T) {
	root := cert("root", "root", []byte{1}, nil)
	inter := cert("inter", "root", []byte{2}, []byte{1})
	leaf := cert("leaf", "inter", nil, []byte{2})
	other := cert("other", "inter", nil, []byte{2})
	// Same issuer name, another key: not issued by inter.
	stranger := cert("stranger", "inter", nil, []byte{9})
	cases := []struct {
		name  string
		certs []*x509.Certificate
		want  *x509.Certificate
	}{
		{"alone", []*x509.Certificate{leaf}, leaf},
		{"leaf first", []*x509.Certificate{leaf, inter, root}, leaf},
		{"leaf last", []*x509.Certificate{root, inter, leaf}, leaf},
		{"self-signed alone", []*x509.Certificate{root}, root},
		{"two leaves", []*x509.Certificate{leaf, other, inter}, nil},
		{"key identifiers disagree", []*x509.Certificate{inter, stranger}, nil},
		{"none", nil, nil},
		{"the same certificate twice", []*x509.Certificate{leaf, leaf}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Leaf(c.certs); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}
