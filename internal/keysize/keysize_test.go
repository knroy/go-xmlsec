package keysize

import (
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec/v2"
)

func TestCheckRSA(t *testing.T) {
	if err := CheckRSA(MaxRSABits); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := CheckRSA(MaxRSABits + 1); !errors.Is(err, xmlsec.ErrUnsupportedKeyInfo) {
		t.Fatalf("over the limit: %v", err)
	}
}
