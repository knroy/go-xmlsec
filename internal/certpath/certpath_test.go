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

// XML-DSig 4.5.4: certificates for one key, such as a re-issue, are one
// leaf; leaves with different keys are still refused.
func TestCertpathLeafOfKey(t *testing.T) {
	withKey := func(c *x509.Certificate, key string) *x509.Certificate {
		c.RawSubjectPublicKeyInfo = []byte(key)
		return c
	}
	inter := withKey(cert("inter", "root", []byte{2}, []byte{1}), "k-inter")
	leaf := withKey(cert("leaf", "inter", nil, []byte{2}), "k-leaf")
	reissued := withKey(cert("leaf-2025", "inter", nil, []byte{2}), "k-leaf")
	other := withKey(cert("other", "inter", nil, []byte{2}), "k-other")
	// Two self-signed certificates for one key and subject issue each other.
	self1 := withKey(cert("self", "self", nil, nil), "k-self")
	self2 := withKey(cert("self", "self", nil, nil), "k-self")
	cases := []struct {
		name  string
		certs []*x509.Certificate
		want  *x509.Certificate
	}{
		{"re-issued leaf", []*x509.Certificate{leaf, reissued, inter}, leaf},
		{"re-issued leaf first", []*x509.Certificate{inter, reissued, leaf}, reissued},
		{"the same certificate twice", []*x509.Certificate{leaf, leaf}, leaf},
		{"self-signed re-issue", []*x509.Certificate{self1, self2}, self1},
		{"two keys", []*x509.Certificate{leaf, reissued, other, inter}, nil},
		{"no key encoded", []*x509.Certificate{cert("a", "x", nil, nil), cert("b", "x", nil, nil)}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LeafOfKey(c.certs); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if c.want != nil && Leaf(c.certs) != nil {
				t.Fatal("Leaf accepted several leaves")
			}
		})
	}
}
