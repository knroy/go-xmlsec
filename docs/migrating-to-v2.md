# Migrating to v2

For go-xmlsec v1 users. v2 moves to go-xml v2, whose parsed trees cannot be
changed, so every call that added to a document now takes an
`*xmlsec.Document`. What is signed, encrypted and verified is unchanged: the
same algorithms, the same allow-lists, the same canonical octets. The
compiler finds every change below except those under
[Behaviour changes](#behaviour-changes).

v1 continues at `github.com/knroy/go-xmlsec` on the `v1` branch, for fixes
only.

## Module path

```go
// v1
import (
    "github.com/knroy/go-xml/c14n"
    "github.com/knroy/go-xml/xdm"
    "github.com/knroy/go-xmlsec"
    "github.com/knroy/go-xmlsec/dsig"
)

// v2
import (
    "github.com/knroy/go-xml/v2/c14n"
    "github.com/knroy/go-xml/v2/xdm"
    "github.com/knroy/go-xmlsec/v2"
    "github.com/knroy/go-xmlsec/v2/dsig"
)
```

```
go get github.com/knroy/go-xmlsec/v2
```

The package names stay `xmlsec`, `dsig`, `wss` and `xenc`.

## go-xml v2

go-xmlsec v2 requires `github.com/knroy/go-xml/v2` v2.0.1. Code of yours that
reads or builds `xdm.Node`s changes with it: fields become methods
(`n.Kind()`, `n.Name()`, `n.Parent()`), `Children()` and `Attrs()` are
iterators, trees are built top-down by appending, and **a parsed tree is
frozen**: appending to it panics. go-xml's
[migration guide](https://github.com/knroy/go-xml/blob/v2.0.1/docs/migrating-to-v2.md)
covers each change, and its `nodeaccess` rewriter does most of them; it
rewrites go-xml imports, not go-xmlsec's.

go-xml's changelog lists no change to canonical output between v1.6.0, the
last pin of go-xmlsec v1, and v2.0.1: signatures made by v1 verify under v2
and the reverse.

## Why xmlsec.Document exists

v1 added to the caller's tree in place: `wss.NewHeader` inserted a
`wsse:Security`, `wss.AssignID` set a `wsu:Id`, `Header.Prepend` and
`dsig.Sign` with `Parent` placed elements. A go-xml v2 tree from `Parse`
allows none of that. Each change now builds a new tree, and something has to
hold the latest one and find a node of an earlier one in it. That is
`xmlsec.Document`:

```go
d := xmlsec.NewDocument(tree.Root)
d.Root()  // the latest tree
d.Node(n) // n's counterpart in it: n from any earlier tree, nil if removed or never in d
```

Functions that only read a document, and return octets or a verdict, still
take an `*xdm.Node`: `dsig.Verify`, `dsig.SignEnveloped`, `BuildManifest`,
`VerifyManifest`, every `xenc` Encrypt and Decrypt function, and the `wss`
receiving functions. After building with a `Document`, pass them `d.Root()`
and `d.Node(x)`.

## dsig.Sign without Parent

The signature is still returned detached, and the document is only read.

```go
// v1
sig, err := dsig.Sign(doc, key, opts)

// v2
d := xmlsec.NewDocument(doc)
sig, err := dsig.Sign(d, key, opts)
```

An enveloping signature still passes nil. Making it a document's element
changes with go-xml:

```go
// v1
sig, err := dsig.Sign(nil, key, opts)
doc := &xdm.Node{Kind: xdm.KindDocument}
doc.AppendChild(sig)

// v2
sig, err := dsig.Sign(nil, key, opts)
t := xdm.NewTree()
t.Root.AppendCopy(sig)
t.Finalize()
```

## dsig.Sign with Parent

```go
// v1: sig is appended to security, inside doc
sig, err := dsig.Sign(doc, key, dsig.SignOptions{ /* ... */ Parent: security})
out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})

// v2: security may be a node of doc or of any later tree of d
d := xmlsec.NewDocument(doc)
sig, err := dsig.Sign(d, key, dsig.SignOptions{ /* ... */ Parent: security})
out, err := c14n.Bytes(d.Root(), c14n.Options{Algorithm: c14n.Inclusive10})
```

On success the returned `sig` is the placed signature, in `d.Root()`
(`sig.Root() == d.Root()`). On failure `d` is unchanged, as v1 left `doc`.

## wss.NewHeader and Header

```go
// v1
hdr, err := wss.NewHeader(doc, xmlsec.NSSOAP12, "", true)
tsID, err := hdr.AddTimestamp(now, 5*time.Minute)
tokID, err := hdr.AddBinarySecurityToken(cert, nil, xmlsec.BSTValueTypeX509v3)
sig, err := dsig.Sign(doc, key, opts)
err = hdr.Prepend(sig)
cov, err := dsig.Verify(doc, sig, vopts)

// v2
d := xmlsec.NewDocument(tree.Root)
hdr, err := wss.NewHeader(d, xmlsec.NSSOAP12, "", true)
tsID, err := hdr.AddTimestamp(now, 5*time.Minute)
tokID, err := hdr.AddBinarySecurityToken(cert, nil, xmlsec.BSTValueTypeX509v3)
sig, err := dsig.Sign(d, key, opts)
err = hdr.Prepend(sig)
cov, err := dsig.Verify(d.Root(), d.Node(sig), vopts)
```

Every `Header` method changes `d`. `hdr.Element()` returns the
`wsse:Security` element of the latest tree, so call it again after each
change rather than keeping the result.

## AssignID and AssignIDWith

```go
// v1
id, err := wss.AssignID(doc, body)
id, err = wss.AssignIDWith(doc, messaging, "msg-1")

// v2: body and messaging may come from tree.Root or any later tree of d
id, err := wss.AssignID(d, body)
id, err = wss.AssignIDWith(d, messaging, "msg-1")
```

The element must be in `d`. v1 also accepted a detached element, such as an
`ek.Element` not yet placed; v2 refuses it with `ErrMalformed`. Place it
first, then assign:

```go
// v1
ekID, err := wss.AssignID(doc, ek.Element)
err = hdr.Prepend(ek.Element)

// v2
err = hdr.Prepend(ek.Element)
ekID, err := wss.AssignID(d, d.Node(ek.Element))
```

If the ID must be known before the element is placed, set it when building
the element instead, as `EncryptOptions.DataID` does for an
`xenc:EncryptedData`, or take a copy carrying one from `wss.WithID`, new in
v2. It sets the ID as `AssignID` would, but with no document to search,
keeping it unique is yours:

```go
// a SecurityTokenReference for SignOptions.KeyInfoElement, named by a
// reference through the STR Dereference Transform
opts.KeyInfoElement, strID, err = wss.WithID(str, "") // "" mints an ID
```

## Passing the latest tree to xenc and dsig.Verify

The `xenc` functions never changed the document and keep their signatures,
but the target must be a node of the tree passed beside it. After a
`Document` has changed, `body` from the parsed tree is not in `d.Root()`:

```go
// v1
out, err := xenc.EncryptContent(doc, body, ek.SessionKey, opts)
cov, err := dsig.Verify(doc, sig, vopts)

// v2
out, err := xenc.EncryptContent(d.Root(), d.Node(body), ek.SessionKey, opts)
cov, err := dsig.Verify(d.Root(), d.Node(sig), vopts)
```

A receiver that parses a message and only verifies or decrypts it needs no
`Document`: pass `tree.Root` as before.

## EncryptedKey methods

`SetKeyInfo`, `AddDataReference` and `AddKeyReference` now replace
`ek.Element` with a new element, a copy with the child in its schema place.
Call them before placing `ek.Element`; a copy already placed is not updated.

```go
// v1: either order worked, since ek.Element was changed in place
err = hdr.Prepend(ek.Element)
err = ek.SetKeyInfo(str)
err = ek.AddDataReference("ED-1")

// v2
err = ek.SetKeyInfo(str)
err = ek.AddDataReference("ED-1")
err = hdr.Prepend(ek.Element)
```

Do not keep `ek.Element` in a variable across these calls.

## Behaviour changes

The compiler does not find these.

- **`Header.Prepend` and `Append` place a copy** of their element. The
  element passed stays detached; `d.Node(el)` is the placed copy. v1 placed
  the element itself.
- **`AssignID` refuses an element not in the document**, such as an
  `ek.Element` not yet placed, with `ErrMalformed`: place it first, or use
  `wss.WithID` (above).
- **The `EncryptedKey` methods replace `ek.Element`** (above). Calling them
  after placing it leaves the placed copy without the change, silently.
- **Each change rebuilds the whole tree**: O(n) in the document's size per
  edit, where v1 edited in place. A message built in k steps costs about k
  copies of it. For SOAP messages of ordinary size this does not matter.
- **The tree you parsed is never changed.** A v1 caller that serialized its
  own tree after `Sign`, `NewHeader` or `AssignID` must now serialize
  `d.Root()`: the original tree still holds the message without the
  signature, header or ID.
