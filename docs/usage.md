# Usage

Every call names its algorithms. There are no defaults: two document families
that commonly meet in one system — WS-Security messages and enveloped
metadata documents — need different canonicalization, and a default would
produce a signature that looks right and that no peer accepts.

| Context | Canonicalization |
|---|---|
| WS-Security, AS4: references and `ds:SignedInfo` | `c14n.Exclusive10` (the WS-I Basic Security Profile requires it) |
| A new inclusive signature | `c14n.Inclusive11`, which XML Signature 1.1 §3.1.1 and §6.5 recommend |
| Enveloped documents whose profile names Canonical XML 1.0, such as SMP metadata | `c14n.Inclusive10` |

Canonicalization algorithm URIs are go-xml's `c14n.Algorithm` constants; this
module does not redefine them.

## Parsing

Parse anything you will verify or decrypt with `xmlsec.Parse`. Its options
are fixed, because the parse is part of the signature: the same octets parsed
two ways can canonicalize two ways. Keep the received octets alongside the
tree.

```go
tree, err := xmlsec.Parse(received)
doc := tree.Root
```

`xmlsec.ParseWithLimits` does the same under tighter limits: set `MaxBytes`,
`MaxDepth` and `MaxNodes` to what your profile needs. Limits can only be
tightened, never loosened, and exceeding one is `ErrLimitExceeded`.

## Signing

`dsig.Sign` returns a detached `ds:Signature` for you to place, and does not
modify the document. A detached signature's `ds:SignedInfo` is canonicalized
before you place it, and only exclusive canonicalization is independent of
where it ends up, so a detached signature needs exclusive canonicalization.
To use any other, set `SignOptions.Parent` to the element the signature
belongs in: `Sign` then appends it there first and computes it in place,
leaves it there, and leaves the document unchanged if it fails.

`Sign` refuses RSA keys under 2048 bits (XML Signature §6.4.2), a
`SignatureID`, `SignedInfoID`, `SignatureValueID`, `KeyInfoID` or
`Reference.ID` that is not an XML name, an Id emitted twice, and a
`Reference.Type` that is not a URI. It refuses with `xmlsec.ErrNotNFC` to
sign a same-document reference, or a `ds:SignedInfo`, whose canonical form is
not in Unicode Normalization Form C (§8.1.3): normalize your content first.

`ds:KeyInfo` and every `ds:Object` are built before any reference is
digested, so a reference to `"#"+KeyInfoID` signs the key information as it
is sent (§4.5 suggests this when it must not be substituted).

Reference forms:

| URI | Transforms | Covers |
|---|---|---|
| `"#id"` | a canonicalization, last | the element with that `wsu:Id` or `xml:id`, or an attribute named in `IDAttributes`; comments removed |
| `"#xpointer(id('id'))"` | a canonicalization, last | as `"#id"`, comments included: use a `#WithComments` algorithm to sign them |
| `""` | `TransformEnvelopedSignature`, then a canonicalization | the whole document minus the enclosing signature; comments removed |
| `"#xpointer(/)"` | `TransformEnvelopedSignature`, then a canonicalization | as `""`, comments included |
| `"cid:..."` | `TransformAttachmentContentSignature`, first | the attachment content, canonicalized: Exclusive C14N for XML types, CRLF line endings for other text, the octets as they are otherwise |
| `"cid:..."` | `TransformAttachmentCompleteSignature`, first | as above, preceded by the canonical Content-Description, -Disposition, -ID, -Location and -Type headers |
| `"#id"` of the signature's own `ds:Object`, `ds:KeyInfo`, or a `ds:Manifest`, `ds:SignatureProperties` or `ds:SignatureProperty` in its `ds:Object` | a canonicalization, last | that element; its unqualified `Id` counts for this signature's own references without `IDAttrDSig` |
| `"http://..."` or relative | any, or none | the octets `ResolveURI` returns; a relative URI needs `BaseURI` (see External references) |
| omitted (`OmitURI: true`) | any that accept octets | `SignOptions.OmittedURIData`; at most one Reference |

Any other XPointer is refused. A canonicalization that follows octets parses
them with `xmlsec.Parse`, and the base64 transform over an element decodes
its text content, as XML Signature §4.4.3.2 and §6.6.2 describe.

When signing, a same-document reference with no transforms, or whose last
transform leaves a node set, is refused: this library never produces a
signature that relies on an implicit canonicalization. When verifying, such a
reference is completed with Canonical XML 1.0, as XML Signature §4.4.3.2
requires, because most signing software relies on exactly that; the implied
algorithm is checked against `AllowedCanonicalizationAlgorithms` like a named
one.

Fill `Attachment.MIMEHeaders` with the part's headers as your MIME parser
returns them: Content-Type selects the content canonicalization, and a part
without one is treated as `text/plain`, so its line endings are normalized.
The digest covers the octets after transfer decoding and before any
decompression; never decompress before verifying. XML attachments are parsed
with `xmlsec.Parse` for canonicalization, under the same limits, and need
Exclusive C14N in `AllowedCanonicalizationAlgorithms`.

`TransformAttachmentContentOnly` and `TransformAttachmentComplete` are the
SwA profile's `EncryptedData` Type URIs, not signature transforms. A
`ds:Transform` naming either is refused: no WS-Security peer accepts it.

### Objects and enveloping signatures

`SignOptions.Objects` adds `ds:Object` elements after `ds:SignatureValue` and
`ds:KeyInfo` (XML Signature §4.6), with optional `ID`, `MimeType` and
`Encoding`; their `Content` nodes are copied, with the namespace bindings in
scope where they stand. Sign builds them before digesting, so a reference to
`"#"+ID` covers one. With a nil document, `Sign` makes an enveloping
signature: references resolve only within the signature, and you make the
returned element a document's element.

```go
sig, err := dsig.Sign(nil, key, dsig.SignOptions{
    SignatureAlgorithm:        xmlsec.SigRSASHA256,
    CanonicalizationAlgorithm: string(c14n.Exclusive10),
    KeyInfo:                   dsig.KeyInfoX509Data,
    Objects:                   []dsig.Object{{ID: "obj", Content: payload.Children}},
    References: []dsig.Reference{{URI: "#obj", DigestAlgorithm: xmlsec.DigestSHA256,
        Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}}},
})
doc := &xdm.Node{Kind: xdm.KindDocument}
doc.AppendChild(sig)
out, err := c14n.Bytes(doc, c14n.Options{Algorithm: c14n.Inclusive10})
```

`Verify` resolves `#obj` to the signature's own `ds:Object` without
`IDAttrDSig`, and still refuses the reference as ambiguous if any other
counted ID attribute in the document carries the same value.

`SignOptions.Properties` adds one `ds:SignatureProperties`, in a `ds:Object`
after the others (§5.2). Each `dsig.SignatureProperty` has an optional `ID`,
a `Target` (empty means `"#"+SignatureID`, which must then be set) and
`Content` holding at least one element in a namespace other than XML
Signature's. It is signed only through a reference to `"#"+ID`:

```go
Properties: []dsig.SignatureProperty{{ID: "time", Content: timestamp}},
References: []dsig.Reference{{URI: "#time", ...}},
SignatureID: "sig",
```

### Manifests

A `ds:Manifest` (§5.1) is a list of references whose validity the
application, not the signature, decides. `dsig.BuildManifest(doc, refs,
opts)` digests `refs` as `Sign` would and returns the Manifest, with its
`Id` from `opts.ManifestID`. Place it in a `ds:Object` and sign it:

```go
m, err := dsig.BuildManifest(doc, refs, dsig.SignOptions{ManifestID: "m"})
sig, err := dsig.Sign(doc, key, dsig.SignOptions{
    ...
    Objects:    []dsig.Object{{Content: []*xdm.Node{m}}},
    References: []dsig.Reference{{URI: "#m", Type: xmlsec.TypeManifest, ...}},
})
```

On receipt, `Verify` checks the signature over the Manifest, not the
Manifest's references. `dsig.VerifyManifest(doc, manifest, cov, opts)`
checks those, with the same allow-lists, transform opt-ins, `MaxReferences`
and resolvers as `Verify`, and returns a `Coverage` of what they cover. It
refuses a Manifest that is not in `cov.SignedElements` (itself, or its
`ds:Object`), with `ErrSignatureInvalid`: an unsigned Manifest proves nothing.

```go
cov, err := dsig.Verify(doc, sig, opts)
mcov, err := dsig.VerifyManifest(doc, manifest, cov, opts)
// inspect mcov exactly as cov
```

### Ids, SignedInfo prefixes and omitted URIs

`SignedInfoID`, `SignatureValueID` and `KeyInfoID` put an `Id` on those
elements (§4.3 to §4.5); `KeyInfoID` needs a `ds:KeyInfo`.

`CanonicalizationPrefixes` becomes the `InclusiveNamespaces` `PrefixList` of
`ds:CanonicalizationMethod` (§4.4.1), with `""` for the default namespace,
and `ds:SignedInfo` is canonicalized with it. It needs an exclusive
algorithm and `Parent`: which listed prefixes are rendered depends on where
the signature stands.

`Reference.OmitURI` emits a reference without a `URI` attribute (§4.4.3.1),
over `SignOptions.OmittedURIData`; the verifier supplies the same octets with
`VerifyOptions.ResolveOmittedURI`. At most one reference may omit its URI.

### HMAC

With `SignOptions.HMACKey`, `Sign` produces an HMAC (§6.3):
`SigHMACSHA256`, `SigHMACSHA384` or `SigHMACSHA512`, keyed with your shared
secret, which must be at least as long as the hash output. The `KeyProvider`
is not used, and `KeyInfo` must be `KeyInfoNone`: nothing about the secret
travels. `HMACOutputLength` truncates the MAC to that many bits, a multiple
of 8 no smaller than half the hash and 80 bits (CVE-2009-0217); zero means
full length. `SigHMACSHA1` stays verification-only.

```go
signed, err := dsig.SignEnveloped(doc, xmlsec.KeyProvider{}, dsig.SignOptions{
    SignatureAlgorithm: xmlsec.SigHMACSHA256, HMACKey: secret, ...})
cov, err := dsig.Verify(d, sig, dsig.VerifyOptions{HMACKey: secret,
    AllowedSignatureAlgorithms: []string{xmlsec.SigHMACSHA256}})
```

### XPath, XPath Filter 2.0 and XSLT transforms

These transforms carry a program, so `Verify` refuses them with
`ErrTransformRefused` unless you allow the exact program. A signer chooses
its own, in the `TransformSpec`:

| Transform | `TransformSpec` fields |
|---|---|
| `TransformXPath` (XML Signature §6.6.3) | `XPath`, the expression; `XPathNamespaces`, the bindings of its prefixes, declared on `ds:XPath` |
| `TransformXPathFilter2` (XPath Filter 2.0) | `XPathFilters`, each a `Filter` (`"intersect"`, `"subtract"` or `"union"`) and an `Expr`; `XPathNamespaces` as above |
| `TransformXSLT` (XML Signature §6.6.5) | `Stylesheet`, the `xsl:stylesheet` element, copied into `ds:Transform` |

```go
noDrafts := dsig.TransformSpec{
	Algorithm:       xmlsec.TransformXPath,
	XPath:           "not(ancestor-or-self::m:Draft)",
	XPathNamespaces: map[string]string{"m": "urn:example:m"},
}
sig, err := dsig.Sign(doc, key, dsig.SignOptions{
	// ...
	References: []dsig.Reference{{URI: "", DigestAlgorithm: xmlsec.DigestSHA256,
		Transforms: []dsig.TransformSpec{
			{Algorithm: xmlsec.TransformEnvelopedSignature},
			noDrafts,
			{Algorithm: string(c14n.Exclusive10)},
		}}},
	Parent: root, // the element the signature goes in
})

cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
	Certificate: cert,
	AllowedXPathExpressions: []dsig.XPathExpression{
		{Expr: "not(ancestor-or-self::m:Draft)", Namespaces: map[string]string{"m": "urn:example:m"}},
	},
})
```

A received expression is accepted when, with surrounding whitespace
trimmed, it equals an allowed `Expr` and each prefix in the entry's
`Namespaces` is bound to the same URI where the expression stands; it is
compiled from the entry, never from the message. A received stylesheet is
accepted when it equals an entry of `AllowedXSLTStylesheets` under Exclusive
C14N with every prefix the entry binds rendered. Anything else is refused
before any cryptographic work.

- Expressions are XPath 1.0, evaluated in go-xml's XPath 1.0 compatibility
  mode. `here()` is the `ds:XPath` (or `dsig-xpath:XPath`) element, so it
  needs a signature computed in place (`SignOptions.Parent`).
- The XPath transform evaluates its expression once for every node of its
  input, namespace and attribute nodes included, and keeps the input nodes
  for which it is true: the output never holds more than the input, for
  example after enveloped-signature or under a `#id` reference.
- XSLT runs with no resolver of any kind: `xsl:include`, `xsl:import`,
  `document()`, `doc()` and `unparsed-text()` fail, and nothing is read
  from a file or the network. Its output is bounded by `xmlsec.MaxParseBytes`.
- A transform that drops part of what a reference names takes it out of
  `Coverage`: an element is listed only when all of its subtree was digested,
  `WholeDocumentSigned` only when nothing but the signature was dropped. An
  XSLT output is new content, so a reference through XSLT appears only in
  `Coverage.References`.

## WS-Security

WS-Security has each step **prepended** to the `wsse:Security` header (SOAP
Message Security 1.1.1 §5, §8.2, §9), so the header lists the steps last
first and a receiver processes it top to bottom.

- `hdr.Prepend(el)` places a signature, an `EncryptedKey` or a
  `ReferenceList`. It keeps two things ahead of the new element: a leading
  timestamp, and every token the element references (Basic Security Profile
  R5205). It refuses an `EncryptedKey` that would land after an
  `EncryptedData` it lists (R3208).
- `AddBinarySecurityToken` and `AddTimestamp` place their elements
  themselves; the timestamp always goes first, at most once.
- `hdr.Append(el)` places an element last, for callers who order the header
  themselves.

Sign, then encrypt:

1. `hdr.AddTimestamp(now, ttl)`.
2. `wss.AssignID` on every element to sign. On an XML Signature or XML
   Encryption element it sets the schema's own unqualified `Id` rather than
   `wsu:Id`; sign such references with `IDAttributes: []xdm.QName{dsig.IDAttrDSig}`.
3. `hdr.AddBinarySecurityToken(signerCert, nil, xmlsec.BSTValueTypeX509v3)`, then
   `dsig.Sign` with `KeyInfo: dsig.KeyInfoSecurityTokenReference` and
   `SecurityTokenID` set to the token's ID, then `hdr.Prepend(sig)`.
4. Name the recipient's key: a token of its certificate and
   `wss.NewSecurityTokenReference`, or `wss.NewKeyIdentifierReference(cert)`
   (subject key identifier, or a SHA-1 thumbprint when the certificate has
   none) or `wss.NewIssuerSerialReference(cert)` when the certificate is not
   sent.
5. `ek.SetKeyInfo(str)`, `ek.AddDataReference(id)`, `hdr.Prepend(ek.Element)`,
   then `xenc.EncryptElement`.

The result reads `wsu:Timestamp`, [recipient token], `xenc:EncryptedKey`,
signer token, `ds:Signature`: a receiver decrypts, then verifies.
`TestWSS4JProcessesSignThenEncrypt` sends exactly this to WSS4J, with each
of the three recipient-key forms.

On an Envelope that uses a default SOAP namespace, `wss.NewHeader` declares a
prefix so that `mustUnderstand` and `actor`/`role` stay SOAP attributes. A
reference to a PKIPath or PKCS7 token carries `wsse11:TokenType`.

### Token types

`AddBinarySecurityToken(cert, chain, valueType)` takes one of three
`ValueType`s from the X.509 Token Profile:

| `valueType` | Carries | Receiver reads |
|---|---|---|
| `xmlsec.BSTValueTypeX509v3` | `cert` alone; `chain` is ignored | that certificate |
| `xmlsec.BSTValueTypeX509PKIPath` | `cert` and `chain` (leaf first, excluding `cert`) as a PkiPath | the last certificate of the path |
| `xmlsec.BSTValueTypePKCS7` | `cert` and `chain`, in any order, as a DER certificates-only PKCS#7 SignedData | the one certificate that issued none of the others |

A PKCS#7 set is unordered, so the receiver finds the leaf by issuer and
subject name and, where both are present, authority and subject key
identifier. `AddBinarySecurityToken` refuses a set in which `cert` would not
be found that way, and more than 16 certificates, with
`ErrUnsupportedKeyInfo`; `ParseBinarySecurityToken` refuses such a token the
same way. On receipt a PKCS7 token must be DER, of type `signedData`,
`SignedData` version 1 with `data` content, carrying only X.509
certificates; CRLs and signer infos, which the profile allows, are ignored.
The Basic Security Profile prefers PKIPath (R5202): send PKCS7 only to a
peer that asks for it. WSS4J does not read PKCS7 tokens.

### Timestamps

```go
ts, err := wss.ParseTimestamp(timestampElement)
err = ts.Check(time.Now(), 5*time.Minute, 10*time.Minute) // skew, maximum age
```

`ParseTimestamp` enforces the Basic Security Profile structure: exactly one
`Created`, an optional `Expires` after it, UTC with `Z`, at most millisecond
precision. `Check` returns `ErrMessageExpired` for an expired, future-dated
or too-old timestamp. A timestamp protects nothing unless the signature's
`Coverage` includes its ID.

### Token references

`wss.ResolveSecurityTokenReference` follows a direct reference to a token in
the message. `wss.ResolveSecurityTokenReferenceStrict` also enforces the
Basic Security Profile rules on how the reference is written: a `ValueType`
matching the token, a consistent `TokenType`, the token in the same header
before the reference. `VerifyOptions.StrictSecurityTokenReference` applies
the strict form inside `dsig.Verify`.

`wss.MatchSecurityTokenReference(str, cert)` checks a key identifier or
issuer-serial reference against a certificate you supply. It never selects a
key from the message.

### Faults

SOAP Message Security §12 names the faults a receiver returns. The library's
errors map onto them as follows; for SOAP 1.2 the Code is `env:Sender` with
the QName as Subcode.

| Error | Fault |
|---|---|
| `ErrUnsupportedAlgorithm`, `ErrAlgorithmNotAllowed`, `ErrTransformRefused` | `wsse:UnsupportedAlgorithm` |
| `ErrUnsupportedKeyInfo` | `wsse:UnsupportedSecurityToken` |
| `ErrIDNotFound` while resolving a token reference | `wsse:SecurityTokenUnavailable` |
| `ErrMalformed` from a token or token reference | `wsse:InvalidSecurityToken` |
| other `ErrMalformed`, `ErrAmbiguousID`, `ErrIDNotFound`, `ErrUnverifiable`, `ErrLimitExceeded`, `ErrAttachmentNotFound` | `wsse:InvalidSecurity` |
| `ErrDigestMismatch`, `ErrSignatureInvalid`, a key-unwrap or decryption failure | `wsse:FailedCheck` |
| `ErrUntrusted` | `wsse:FailedAuthentication` |
| `ErrMessageExpired` | `wsse:MessageExpired` |

## SAML, XAdES and other ID attributes

By default `"#id"` resolves only `wsu:Id` and `xml:id`. To sign or verify
documents that use another ID attribute, name it in `SignOptions.IDAttributes`
and `VerifyOptions.IDAttributes`. `dsig.IDAttrSAML` is SAML 2.0's unqualified
`ID`, and `dsig.IDAttrDSig` is the unqualified `Id` used by XML Signature's
own schema, XAdES and many other profiles.

```go
cov, err := dsig.Verify(doc, sig, dsig.VerifyOptions{
    Certificate:  idpCert,
    IDAttributes: []xdm.QName{dsig.IDAttrSAML},
})
// Then confirm cov.SignedElements[0] is the assertion you will read.
```

The listed attributes add to `wsu:Id` and `xml:id` and never replace them.
Name only what your profile defines as an ID, and use the same list when
signing and verifying. `wss.FindByID(doc, id, attrs...)` does the same
lookup directly.

## Enveloped signature

```go
signed, err := dsig.SignEnveloped(doc, key, dsig.SignOptions{
    SignatureAlgorithm:        xmlsec.SigRSASHA256,
    CanonicalizationAlgorithm: string(c14n.Inclusive10),
    References: []dsig.Reference{{
        URI:             "",
        DigestAlgorithm: xmlsec.DigestSHA256,
        Transforms: []dsig.TransformSpec{
            {Algorithm: xmlsec.TransformEnvelopedSignature},
            {Algorithm: string(c14n.Inclusive10)},
        },
    }},
    KeyInfo: dsig.KeyInfoX509Data,
})
```

The signature is appended as the last child of the document element, and the
signed document is returned as octets in canonical form (`Inclusive10WithComments`,
so comments survive; there is no XML declaration). `doc` is left unmodified.
Transmit exactly the returned octets and never re-serialize.

## Verifying

```go
cov, err := dsig.Verify(doc, sigElement, dsig.VerifyOptions{
    AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
    AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
    AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
    Attachments:                       atts,
})
```

Pass exactly the algorithms your profile permits. An empty list means the
default set: every secure algorithm this library implements. An algorithm
kept only for legacy interoperability is outside that set and is accepted
only when named explicitly.

Legacy algorithms verify only when listed: `SigRSASHA1`, `SigDSASHA1`,
`SigHMACSHA1` and `DigestSHA1`. `Sign` never produces them. The HMAC-SHA2
constants are also outside the default set, and verify only when listed and
keyed with `HMACKey`; `Sign` produces them with `SignOptions.HMACKey`.

To pin a sender known by a raw key rather than a certificate, set
`VerifyOptions.PublicKey` instead of `Certificate`; setting both is an
error. With a key pinned, a `KeyInfo` form this library does not accept is
ignored (`KeyInfoForm` is then `KeyInfoNone`); a malformed or ambiguous one is
still refused. When signing, `KeyInfoKeyValue` and
`KeyInfoDEREncodedKeyValue` emit the signer's key without a certificate. A
`dsig11:KeyInfoReference` is followed to a `ds:KeyInfo` in the same document,
never further.

More options:

| Option | Effect |
|---|---|
| `TrustKey func(cert *x509.Certificate, key crypto.PublicKey) error` | Called with the signer's key, and its certificate when there is one, before any cryptographic or digest work; an error stops verification with `ErrUntrusted`. Use it when you cannot pin one certificate but know which you accept: a refused sender costs nothing to process. |
| `RequireExplicitCanonicalization` | Refuse a reference that relies on the Canonical XML 1.0 implied by XML Signature §4.4.3.2, even when that algorithm is in the allow-list. Off by default, because most signers rely on it. |
| `StrictSecurityTokenReference` | Resolve a `wsse:SecurityTokenReference` with the Basic Security Profile rules; see Token references above. |
| `HMACKey []byte` | The secret for an HMAC signature, the only HMAC key there is: never taken from the message, not combinable with `Certificate` or `PublicKey`, and a non-HMAC signature then fails. The HMAC algorithm must also be named in the allow-list. |
| `AllowedXPathExpressions []dsig.XPathExpression`, `AllowedXSLTStylesheets []*xdm.Node` | Opt in to the XPath, XPath Filter 2.0 and XSLT transforms for exactly these programs; see [XPath, XPath Filter 2.0 and XSLT transforms](#xpath-xpath-filter-20-and-xslt-transforms). Empty refuses them. |
| `ResolveOmittedURI func() ([]byte, error)` | Supplies the data of the one `ds:Reference` without a URI that XML Signature §4.4.3.1 allows; `Coverage.OmittedURISigned` reports that it was covered. Without it, such a reference is refused. |
| `ResolveURI xmlsec.URIResolver` | Supplies the octets of a reference to an absolute URI such as `http:`; see External references below. Without it, such a reference is refused. |
| `BaseURI string` | The absolute URI a relative reference URI is resolved against before `ResolveURI` sees it; never taken from the document. Without it, a relative URI is refused. |
| `RequireNFC` | Refuse with `ErrNotNFC` a `ds:SignedInfo`, or the canonical octets of a same-document reference, that is not in Unicode Normalization Form C. Off by default. |

Then check `Coverage`, every time:

| Field | Check |
|---|---|
| `Covers(ids...)` / `SignedElements` | every element your profile requires is signed; compare identity, not just ID, when you locate elements by position |
| `CoversAttachments(ids...)` | every attachment is signed |
| `WholeDocumentSigned` | set for an enveloped signature |
| `ExternalURIs` | the absolute URIs your `ResolveURI` supplied; what it returned is what was signed |
| `KeyInfoForm` | the key was described the way your profile requires |
| `Certificate` | **you** establish that it is trusted |
| `PublicKey` | the key the signature was verified with; `Certificate` is nil when it was a raw key |
| `References` | the digests, for receipts that echo them; `Raw` is each `ds:Reference` in the SignedInfo's canonical form |

Errors worth distinguishing, all matchable with `errors.Is`:

| Error | Meaning |
|---|---|
| `ErrUnverifiable` | the document has no canonical form (XML 1.1, or a relative namespace URI). Permanent: never retry. Wraps the `c14n` cause. |
| `ErrAlgorithmNotAllowed` | outside your allow-list; rejected before any cryptography |
| `ErrAmbiguousID` | an ID appears more than once |
| `ErrDigestMismatch` / `ErrSignatureInvalid` | the content or the signature value does not match |
| `ErrTransformRefused` | an XPath, XPath Filter 2.0 or XSLT transform whose program you did not allow |
| `ErrUntrusted` | your `TrustKey` refused the signer |
| `ErrDereference` | your `ResolveURI` failed; wraps its error |

### External references

A `ds:Reference` to an absolute URI other than `cid:`, such as
`http://example.com/data.xml`, is dereferenced only through a
`xmlsec.URIResolver` you pass as `SignOptions.ResolveURI` or
`VerifyOptions.ResolveURI`. The library never fetches anything itself. The
octets you return go through the reference's transforms as an octet stream:
with none they are digested as they are, and a canonicalization parses them
with `xmlsec.Parse` first, under the same limits. A relative URI, such as
`data.xml`, is refused unless you set `BaseURI` on `SignOptions` and
`VerifyOptions`: it is then resolved against that (RFC 3986), your resolver
gets the absolute URI, and `Coverage.ExternalURIs` reports it. The base is
always yours, never `xml:base` or anything else the signer wrote.

```go
allowed := map[string]bool{"http://example.com/schema.xml": true}
client := &http.Client{Timeout: 5 * time.Second}
resolve := func(uri string) ([]byte, error) {
    if !allowed[uri] {
        return nil, fmt.Errorf("%s is not on the allow-list", uri)
    }
    resp, err := client.Get(uri)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("%s: %s", uri, resp.Status)
    }
    b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
    if err == nil && len(b) > 1<<20 {
        err = fmt.Errorf("%s: larger than 1 MiB", uri)
    }
    return b, err
}
cov, err := dsig.Verify(doc, sigElement, dsig.VerifyOptions{Certificate: cert, ResolveURI: resolve})
// cov.ExternalURIs lists the URIs whose octets were signed.
```

On verification the resolver is called only after every algorithm has
passed the allow-lists, `TrustKey` has accepted the key and the signature
value has verified, so a message from a key you do not trust never makes
you fetch. The URIs are still the signer's choice: resolve an allow-list,
with timeouts and a size cap, as above, and give the client a
`CheckRedirect` that refuses what the allow-list would.
`xenc.DecryptOptions.ResolveURI` does the same for an external
`xenc:CipherReference` in `DecryptData`: its octets are the ciphertext, or,
with the base64 transform, its encoding. A relative `CipherReference` URI is
resolved against `DecryptOptions.BaseURI`, which you set to where the
message came from; the document's `xml:base` is never used, and without
`BaseURI` a relative URI is refused.

A `CipherReference` may also select the ciphertext's base64 text inside an
XML document with an XPath transform, as XML Encryption's Example 13 does.
That transform is refused unless its expression is one you allow, matched
as `dsig.VerifyOptions.AllowedXPathExpressions` matches (the same text, each
prefix bound to the same namespace), before anything is fetched:

```go
pt, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{
    BaseURI:    "https://repository.example/msgs/1.xml",
    ResolveURI: resolve, // an allow-list, as above
    AllowedXPathExpressions: []dsig.XPathExpression{{
        Expr:       `self::text()[parent::rep:CipherValue[@Id="example1"]]`,
        Namespaces: map[string]string{"rep": "http://www.example.org/repository"},
    }},
})
```

The resolved octets are parsed with `xmlsec.Parse`; the text nodes the
expression keeps are concatenated and decoded. XSLT and XPath Filter 2.0 on a
`CipherReference` are always refused.

## Encryption

Sign first, then encrypt, so the signature covers the plaintext and the
encryption covers the signature. A receiver decrypts, then verifies.

```go
opts := xenc.EncryptOptions{
    DataAlgorithm:         xmlsec.EncAES128GCM,
    KeyTransportAlgorithm: xmlsec.KeyTransportRSAOAEP,
    MGFAlgorithm:          xmlsec.MGF1SHA256,
    DigestAlgorithm:       xmlsec.DigestSHA256,
    Recipient:             recipientCert,
}
ek, err := xenc.GenerateEncryptedKey(opts)
defer clear(ek.SessionKey)
// For a second recipient, wrap the same key: set opts.SessionKey =
// ek.SessionKey and opts.Recipient, and call GenerateEncryptedKey again.

ciphertext, ed, err := xenc.EncryptAttachment(att, ek.SessionKey, xmlsec.TransformAttachmentContentOnly, opts)
// Replace the MIME body with ciphertext, Content-Type application/octet-stream,
// place ek.Element and ed in the security header.
```

Pass `xmlsec.TransformAttachmentComplete` instead to encrypt the listed MIME
headers with the body. Then keep Content-ID on the part and drop the other
listed headers.

The MGF is emitted explicitly. Omitting it means SHA-1 by specification
default, so `DecryptEncryptedKey` refuses an `EncryptedKey` without one.
`xmlsec.MGF1SHA224` is produced when you name it, and accepted only when
`AllowedMGFAlgorithms` names it.

What to encrypt:

| Function | Encrypts | Type |
|---|---|---|
| `xenc.EncryptElement(doc, el, key, opts)` | an element, in place of itself | `xenc#Element` |
| `xenc.EncryptContent(doc, el, key, opts)` | an element's content, such as the SOAP Body's | `xenc#Content` |
| `xenc.EncryptHeader(doc, block, security, key, opts)` | a SOAP header block, as a `wsse11:EncryptedHeader` carrying the Security header's `mustUnderstand` and `actor`/`role` | `xenc#Element` |
| `xenc.EncryptAttachment(att, key, transform, opts)` | a MIME part, by `CipherReference` | the SwA Type |
| `xenc.EncryptOctets(octets, key, opts)` | arbitrary octets, inline or by `CipherReference` | `opts.Type`, or none |

`EncryptElement` refuses the SOAP Envelope, Header and Body and any header
block: a header block must become an `EncryptedHeader` (Basic Security
Profile R3228, R5614). Plaintext must be in Unicode Normalization Form C
(`xmlsec.ErrNotNFC`); it is refused, never normalized, since it may already be
signed. An element that undeclares a default namespace is encrypted with
`xmlns=""`, so a peer that decrypts in place keeps it out of its parent's
namespace. `EncryptOptions.DataID` must be an XML name.

A WS-Security receiver finds the session key through the `EncryptedKey` in
the header: its `ds:KeyInfo` names the recipient's key, and its
`xenc:ReferenceList` names each `EncryptedData` it decrypts:

```go
opts.DataID = "ED-1"                    // the Id the EncryptedData will carry
ek, err := xenc.GenerateEncryptedKey(opts)
err = ek.SetKeyInfo(str)                // which key unwraps it
err = ek.AddDataReference(opts.DataID)  // what it decrypts
err = hdr.Prepend(ek.Element)
encrypted, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
```

`EncryptOptions.CarriedKeyName` and `RecipientHint` emit the `EncryptedKey`'s
`CarriedKeyName` and `Recipient`. `SetKeyInfo` and `AddDataReference` place
what they add in schema order, whatever order they are called in.

Arbitrary octets, such as an image or a PDF, are encrypted with
`EncryptOctets`. `Type`, `MimeType` and `Encoding` tell the recipient what
they are; all three are optional, and `MimeType` and `Encoding` are advisory.
With `CipherReferenceURI` the ciphertext is returned for you to store at
that URI, and the `EncryptedData` points at it:

```go
ciphertext, ed, err := xenc.EncryptOctets(pdf, ek.SessionKey, xenc.EncryptOptions{
    DataAlgorithm:      xmlsec.EncAES128GCM,
    MimeType:           "application/pdf",
    CipherReferenceURI: "https://repository.example/ct/1.bin", // omit for an inline CipherValue
})
// Store ciphertext at the URI; ciphertext is nil without CipherReferenceURI.
```

`MimeType`, `Encoding` and `EncryptionProperties` apply to `EncryptElement`,
`EncryptContent` and `EncryptHeader` too; `EncryptAttachment` takes the
`MimeType` from the part's Content-Type. `EncryptionProperties` are
`xenc:EncryptionProperty` elements, such as a timestamp, copied after the
`CipherData` (section 3.7) with the namespaces in scope where they stand.
`Type` is set by each function itself, and `CipherReferenceURI` is only for
`EncryptOctets`: any other value is refused.

Key agreement and key wrap:

- **ECDH-ES** (P-256, P-384, P-521, with ConcatKDF): set
  `KeyTransportAlgorithm: xmlsec.KeyWrapAES128` (or 192, 256),
  `KeyAgreementAlgorithm: xmlsec.KeyAgreementECDHES`, `DigestAlgorithm` for
  the KDF, and an EC `Recipient`. The receiver calls
  `xenc.DecryptAgreedKey(ek, priv.ECDH(), xenc.DecryptOptions{})`.
- **AES key wrap** with a key you share: set `KeyEncryptionKey`, and receive
  with `xenc.UnwrapEncryptedKey`.
- **Finite-field Diffie-Hellman** and **a password (PBKDF2)**: OPTIONAL, and
  opt-in on receipt; see below.

Receiving:

```go
edKey, err := xenc.FindEncryptedKey(edElement) // inline, RetrievalMethod, KeyName, or ReferenceList
allow := xenc.DecryptOptions{ // empty lists mean the secure defaults
    AllowedDataAlgorithms:         []string{xmlsec.EncAES128GCM},
    AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEP},
    AllowedMGFAlgorithms:          []string{xmlsec.MGF1SHA256},
    AllowedDigestAlgorithms:       []string{xmlsec.DigestSHA256},
}
key, err := xenc.DecryptEncryptedKey(edKey, decrypter, allow)
att, err := xenc.DecryptAttachment(edElement, mimeBody, key, allow)
// Replace the part's body with att.Body, and its headers of the same names
// with att.MIMEHeaders.
```

`xenc.DecryptData` returns the plaintext octets. To put them back in the
document, as a decryptor does (sections 4.1 and 4.5), use `DecryptAndReplace`:

```go
doc, err := xenc.DecryptAndReplace(received, edElement, key, allow)
// doc is the canonical document with the element, or the content, in place
// of the EncryptedData; received is left unmodified.
```

It parses the plaintext with `xmlsec.Parse` as the content of an element
declaring the namespaces in scope at the `EncryptedData`'s parent, so an
element without a prefix takes its parent's default namespace unless it
carries `xmlns=""`. `Element` must decrypt to one element, and so must an
`EncryptedData` that is the document element; anything else, or another
`Type`, is refused.
`DecryptData` also follows a same-document `CipherReference` with the base64
transform. `EncryptionMethod` is read strictly: a child the algorithm does not
permit, or a `KeySize` inconsistent with it, is refused.

### Finite-field Diffie-Hellman and passwords

XML Encryption 1.1's OPTIONAL key establishment, none of it in a default
allow-list. Diffie-Hellman keys are `xenc.DHPublicKey` and
`xenc.DHPrivateKey` (`math/big` P, Q, G, Y and X), in a group of 2048 to
8192 bits with its subgroup order Q, such as RFC 7919 ffdhe2048, whose Q is
(P-1)/2:

```go
recipient, err := xenc.GenerateDHKey(p, q, g) // checks the group

ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{
    DataAlgorithm:         xmlsec.EncAES128GCM,
    KeyTransportAlgorithm: xmlsec.KeyWrapAES128,
    KeyAgreementAlgorithm: xmlsec.KeyAgreementDHES, // or KeyAgreementDH, the Legacy KDF
    DigestAlgorithm:       xmlsec.DigestSHA256,     // ConcatKDF, or Legacy KDF, digest
    RecipientDH:           &recipient.DHPublicKey,
    RecipientKeyName:      "recipient",             // optional; xmlsec1 finds the key only by name
})

key, err := xenc.DecryptAgreedKeyDH(ek, recipient, xenc.DecryptOptions{
    AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementDHES},
})
```

The receiver checks that the originator's public value lies in its own
group's order-Q subgroup, and refuses any other group.

A password derives the KEK by PBKDF2 with HMAC-SHA256, a fresh 16-octet salt
and 600,000 iterations unless `PBKDF2Iterations` says otherwise; the
parameters travel in an `xenc11:DerivedKey`:

```go
ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{
    DataAlgorithm:         xmlsec.EncAES256GCM,
    KeyTransportAlgorithm: xmlsec.KeyWrapAES256,
    Password:              password,
})

key, err := xenc.UnwrapEncryptedKeyPassword(ek, password, xenc.DecryptOptions{
    AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2},
})
```

A received iteration count over `xenc.MaxPBKDF2Iterations` (10,000,000) is
refused before any work, and one under 1000 as weak. The HMAC-SHA1 PRF is
accepted only when `AllowedPRFAlgorithms` names `xmlsec.SigHMACSHA1`.
Naming `xmlsec.KeyDerivationPBKDF2` also lets `DecryptAgreedKey` and
`DecryptAgreedKeyDH` accept PBKDF2 as a key agreement's KDF, with the shared
secret as the password.

### Key chains, derived keys and direct key agreement

The other `ds:KeyInfo` forms of sections 3.5 and 5.6, each found the same
ways: a child of the `KeyInfo`, a same-document `ds:RetrievalMethod` (or
several naming one element; naming two is `xmlsec.ErrAmbiguousID`), a
`ds:KeyName`, or, with no `KeyInfo`, the one key whose `xenc:ReferenceList`
names the element by `DataReference` (for an `EncryptedData`) or
`KeyReference` (for an `EncryptedKey`).

An `EncryptedKey` whose KEK another `EncryptedKey` carries: `FindEncryptedKey`
takes either element and returns the next key, one hop per call. Bound the
walk yourself; a key naming itself is refused.

```go
ek1, err := xenc.FindEncryptedKey(ed)  // the data key's EncryptedKey
ek2, err := xenc.FindEncryptedKey(ek1) // the one carrying its KEK
kek, err := xenc.DecryptEncryptedKey(ek2, decrypter, allow)
key, err := xenc.UnwrapEncryptedKey(ek1, kek, allow)

// Sending: KeyReference is the KEK's ReferenceList entry for ek1's Id.
err = kekEK.AddKeyReference("EK-1")
```

A data key derived from a master key you share (`xenc11:DerivedKey`,
ConcatKDF with a fresh 16-octet `PartyUInfo`, so each key is new), or from
a password (PBKDF2), with no `EncryptedKey`. Pass no session key:

```go
out, err := xenc.EncryptElement(doc, payload, nil, xenc.EncryptOptions{
    DataAlgorithm:   xmlsec.EncAES256GCM,
    DigestAlgorithm: xmlsec.DigestSHA256, // the ConcatKDF digest
    MasterKey:       master,              // at least the data key's length
    MasterKeyName:   "Our other secret",  // optional, as is DerivedKeyName
})

dk, err := xenc.FindDerivedKey(ed)
key, err := xenc.DeriveKey(dk, ed, master, xenc.DecryptOptions{})
pt, err := xenc.DecryptData(ed, key, xenc.DecryptOptions{})
```

`DeriveKey` takes the size from the target's algorithm after its allow-list,
and its target may be an `EncryptedKey`, whose KEK it derives. With
`Password` instead of `MasterKey` the `DerivedKey` names PBKDF2, which
`DeriveKey` accepts only when `AllowedKeyDerivationAlgorithms` names it.

The data key agreed directly, with the `AgreementMethod` in the
`EncryptedData` (ECDH-ES, or `dh-es` and `dh` with `RecipientDH`):

```go
opts := xenc.EncryptOptions{
    DataAlgorithm:         xmlsec.EncAES128GCM,
    KeyAgreementAlgorithm: xmlsec.KeyAgreementECDHES,
    DigestAlgorithm:       xmlsec.DigestSHA256,
    Recipient:             ecCert,
    DirectKeyAgreement:    true,
}
out, err := xenc.EncryptElement(doc, payload, nil, opts)

key, err := xenc.DecryptAgreedDataKey(ed, priv.ECDH(), xenc.DecryptOptions{})
// finite-field: xenc.DecryptAgreedDataKeyDH(ed, dhPriv, opts)
```

A `KA-Nonce` beside ECDH-ES or `dh-es` is accepted and ignored: ConcatKDF
has no use for it.

An `EncryptedKey` may carry its ciphertext by `xenc:CipherReference`, like an
`EncryptedData`; every unwrap function resolves it the same way, through
`DecryptOptions.ResolveURI` for an external URI, after the algorithms pass
their allow-lists and before any decryption.

Without an `EncryptionMethod`, the algorithm "must be known to the
recipient" (section 3.1): name it in `DecryptOptions.ImpliedDataAlgorithm`,
`ImpliedKeyWrapAlgorithm` or `ImpliedKeyTransportAlgorithm`. It is used only
for an element with none, and passes the allow-list like an explicit one.

### Receiving from a legacy peer

A peer that still sends the older algorithms can be decrypted, never
answered in kind: name every legacy part, and nothing else.

```go
// AES-CBC data under rsa-oaep-mgf1p (SHA-1).
legacy := xenc.DecryptOptions{
    AllowedDataAlgorithms:         []string{xmlsec.EncAES128CBC},
    AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSAOAEPMGF1P},
    AllowedMGFAlgorithms:          []string{xmlsec.MGF1SHA1},
    AllowedDigestAlgorithms:       []string{xmlsec.DigestSHA1},
}
key, err := xenc.DecryptEncryptedKey(ek, decrypter, legacy)
pt, err := xenc.DecryptData(ed, key, legacy)

// RSA v1.5: a separate function, and a key pair used for nothing else.
key, err = xenc.DecryptEncryptedKeyPKCS1v15(ek, ed, v15OnlyDecrypter, xenc.DecryptOptions{
    AllowedKeyTransportAlgorithms: []string{xmlsec.KeyTransportRSA15},
    AllowedDataAlgorithms:         []string{xmlsec.EncTripleDESCBC},
})
```

An absent `DigestMethod` or `MGF` means SHA-1 and is named the same way.
`kw-tripledes` unwraps through `UnwrapEncryptedKey` when named. No encryption
function will produce any of these.
