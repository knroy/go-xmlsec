package xmlsec

// URIResolver returns the octets an absolute URI names, for a ds:Reference
// or xenc:CipherReference that is neither same-document nor cid:. It is
// called with an absolute URI, such as "http://example.com/data.xml": the
// URI as it appears in the document, or a relative one resolved against the
// caller's BaseURI (dsig.SignOptions, dsig.VerifyOptions,
// xenc.DecryptOptions), never against xml:base. Without a BaseURI a
// relative URI is refused and never passed.
//
// This library never performs network or file I/O: an external reference
// is dereferenced only through a URIResolver the caller supplies, and is
// refused without one. The resolver is therefore the caller's server-side
// request forgery boundary. A safe one serves only an allow-list of hosts or
// a fixed set of local resources, sets connect and read timeouts, caps the
// size it returns, and refuses redirects to anywhere it would not fetch
// directly. An error it returns is wrapped with ErrDereference.
//
// It is a function rather than an interface because it has one operation
// and is usually a closure over the caller's HTTP client or file set.
type URIResolver func(uri string) ([]byte, error)
