// Package w3c runs the W3C interoperability test vectors against
// go-xmlsec: the XML Signature 1.1 vectors, asserting each outcome recorded
// in testdata/MANIFEST.json, and the XML Encryption 1.1 vectors in
// testdata/xmlenc11, asserting the outcomes listed in xmlenc_test.go.
//
// The vectors are third-party documents under the W3C Document License,
// not this repository's MIT license: see NOTICE and LICENSE-W3C-DOCUMENT.
// They live in this nested module so that they are not part of the
// library's module download.
package w3c
