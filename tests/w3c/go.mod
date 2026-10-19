module github.com/knroy/go-xmlsec/v2/tests/w3c

go 1.26.0

require (
	github.com/knroy/go-xml/v2 v2.0.1
	github.com/knroy/go-xmlsec/v2 v2.0.0
)

require golang.org/x/text v0.41.0 // indirect

// The library in this repository, not a published version: these vectors
// test the working tree. A separate module, so the vectors never ship in
// the library's module download.
replace github.com/knroy/go-xmlsec/v2 => ../..
