# Usage

Every call that produces a signature or ciphertext names its algorithms:
two document families that commonly meet in one system — WS-Security
messages and enveloped metadata documents — need different canonicalization,
and a default would produce a signature that looks right and that no peer
accepts. Verification and decryption have conservative default allow-lists,
which a caller replaces by naming its own.

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
tree. A DOCTYPE is refused with `xmlsec.ErrMalformed`; no option enables
it.

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

For the same reason, without `Parent` a reference to an element of the
signature itself — its `ds:Object`, `ds:KeyInfo`, or a token embedded in its
`wsse:SecurityTokenReference` — is refused with
`xmlsec.ErrUnsupportedAlgorithm` unless its transforms are exclusive
canonicalization without `InclusiveNamespacePrefixes`, enveloped-signature or
base64 (§4.4.3.3): an inclusive canonicalization, an XPath or XSLT transform,
or the STR Dereference Transform would digest the element before you place
it, and the digest would no longer match. An enveloping signature, with `doc`
nil, has no surroundings to change and is exempt.

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
its text content, as XML Signature §4.4.3.2 and §6.6.2 describe. The base64
transform ignores every character outside the base64 alphabet, as RFC 2045
§6.8 requires, not only whitespace; `ds:DigestValue` and
`ds:SignatureValue`, which are `base64Binary`, still admit only whitespace.

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
The enveloped-signature transform of a Manifest reference removes the
`ds:Signature` containing the Manifest; in a Manifest outside any signature
it has no output (§6.6.4), and `VerifyManifest` refuses it with
`ErrMalformed`. `BuildManifest` digests before the Manifest is placed, so
such a reference is valid once the Manifest stands in the signature's
`ds:Object`, as above.

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
`SigHMACSHA224`, `SigHMACSHA256`, `SigHMACSHA384` or `SigHMACSHA512`, keyed
with your shared secret, which must be at least as long as the hash output. The `KeyProvider`
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
| `TransformXPathFilter2` (XPath Filter 2.0) | `XPathFilters`, each a `dsig.XPathFilter` with a `Filter` (`"intersect"`, `"subtract"` or `"union"`) and an `Expr`; `XPathNamespaces` as above |
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
- `AddBinarySecurityToken`, `AddTimestamp` and `AddSignatureConfirmation`
  place their elements themselves; the timestamp always goes first, at most
  once.
- `hdr.Append(el)` places an element last, for callers who order the header
  themselves.

Sign, then encrypt:

1. `hdr.AddTimestamp(now, ttl)`.
2. `wss.AssignID` on every element to sign. On an XML Signature or XML
   Encryption element it sets the schema's own unqualified `Id` rather than
   `wsu:Id`; sign such references with `IDAttributes: []xdm.QName{dsig.IDAttrDSig}`.
   An element that already has an `xml:id` keeps it (§4 forbids both).
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
`Created` (BSP R3203; SOAP Message Security makes it optional, but a
timestamp without it is refused), an optional `Expires` after it, UTC
written with `Z` or a zero offset (`+00:00`). More than three fractional
digits, which BSP says SHOULD NOT be sent, are accepted; `AddTimestamp`
sends milliseconds. `Check` returns `ErrMessageExpired` for an expired,
future-dated or too-old timestamp. A timestamp protects nothing unless the
signature's `Coverage` includes its ID.

**A timestamp without `Expires` never expires.** `ts.Check(now, skew, 0)`
accepts it however old it is; only a `Created` in the future fails. Unless
your policy requires `Expires`, always pass a non-zero `maxAge`, as above.

### Token references

`wss.ResolveSecurityTokenReference` follows a direct reference to a token in
the message, or reads the token a `wsse:Embedded` holds (§7.4), and returns
its certificate. `wss.ResolveSecurityTokenReferenceStrict` also enforces the
Basic Security Profile rules on how the reference is written: a `ValueType`
matching the token, a consistent `TokenType`, the token in the same header
before the reference. `VerifyOptions.StrictSecurityTokenReference` applies
the strict form inside `dsig.Verify`. The same-header rule (R3066) applies
to a reference inside a `wsse:Security`; one outside every header, such as
in the Body, need only follow its token in document order (R5205). The
strict form also refuses a binary security token without an `EncodingType`
(R3029), which the lenient one reads as Base64Binary, the default of §6.3. `wss.ReferencedToken` returns the
token element of either form, of any kind: a binary security token, an
`xenc:EncryptedKey`, a SAML assertion. All three refuse a reference to
another reference, to a `wsse:Embedded` or to a `ds:KeyInfo` (R3057, R3064,
R3211), and an `Embedded` holding anything but one token (R3060, R3056). A
reference to an ID nothing carries is `ErrSecurityTokenUnavailable`, as well
as `ErrIDNotFound`. `wss.CheckSecurityTokenReference` applies the profile's
syntax rules to any reference: one reference (R3061), no `KeyName` (R3027),
a `URI` on a direct reference (R3062), a key identifier with a `ValueType`
(R3054) and the Base64Binary `EncodingType` (R3070, R3071), or none for a
SAML one (R6604), and a `TokenType` consistent with it (§7.1, R3069; on a
direct reference to an `EncryptedKey` too). A key identifier of a profile
this library does not read, such as Kerberos, is `ErrUnsupportedKeyInfo`.

`wss.MatchSecurityTokenReference(str, cert)` checks a key identifier or
issuer-serial reference against a certificate you supply. It never selects a
key from the message.

To name, in a signature's `ds:KeyInfo`, a certificate that does not travel
with the message (X.509 Token Profile §3.2, BSP R5417, R5209), pass the reference as
`SignOptions.KeyInfoElement` with `KeyInfo: dsig.KeyInfoSecurityTokenReference`:

```go
str, err := wss.NewKeyIdentifierReference(signerCert) // or NewIssuerSerialReference
sig, err := dsig.Sign(doc, key, dsig.SignOptions{
	// ...
	KeyInfo:        dsig.KeyInfoSecurityTokenReference,
	KeyInfoElement: str, // Sign takes it: build one per signature
})
```

The receiver pins the certificate, or supplies it through
`VerifyOptions.ResolveSecurityToken`, a lookup in its own store that never
fetches:

```go
opts.ResolveSecurityToken = func(str *xdm.Node) (*x509.Certificate, error) {
	for _, c := range trusted {
		if wss.MatchSecurityTokenReference(str, c) {
			return c, nil
		}
	}
	return nil, errors.New("unknown certificate")
}
```

With a certificate pinned and `StrictSecurityTokenReference` or `StrictBSP`
set, a key identifier or issuer serial that names another certificate is
`ErrUnsupportedKeyInfo`. Lenient verification ignores it, as it ignores any
`ds:KeyInfo` under a pinned key.

An `xenc:EncryptedKey` is a token too (§7.7):
`wss.NewEncryptedKeyReference(ekID)` references one in the same message
(the element `NewSecurityTokenReference` builds for the `EncryptedKey`
ValueType, as the symmetric binding below uses), and
`wss.NewEncryptedKeySHA1Reference(ek)` names one from an earlier message by
the SHA-1 of its `CipherValue` octets; `wss.MatchEncryptedKeySHA1(str, ek)`
finds which key a reply names. Both carry the `TokenType` BSP requires.

### STR Dereference Transform

The STR Dereference Transform (`xmlsec.TransformSTR`, §8.3) signs the token
a `wsse:SecurityTokenReference` names rather than the reference: put the
reference in the header with an ID and make the transform the reference's
only transform.

```go
str, err := wss.NewSecurityTokenReference(doc, tokenID, "")
hdr.Append(str)
strID, err := wss.AssignID(doc, str)
refs = append(refs, dsig.Reference{URI: "#" + strID, DigestAlgorithm: xmlsec.DigestSHA256,
	Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformSTR}}})
```

`Sign` serializes the token with Exclusive C14N, stated in
`wsse:TransformationParameters` with `TransformSpec.InclusiveNamespacePrefixes`
and `#default` as its PrefixList, and `xmlns=""` on the token when no
default namespace is in scope, as §8.3 requires. The default namespace is
always inclusive, as WSS4J reads §8.3, so `Sign` states it, and `Verify`
applies it to a received transform whether its PrefixList states it or not
(WSS4J's does not). `Verify` accepts any canonicalization
`AllowedCanonicalizationAlgorithms` admits, such as the Inclusive C14N of
the §8.3 example; `StrictBSP` requires Exclusive C14N (R5404).

An X509SubjectKeyIdentifier or ThumbprintSHA1 key identifier, or an
issuer-serial reference, names a certificate outside the message: the
transform digests the X509v3 `wsse:BinarySecurityToken` §8.3 builds from
the certificate `SignOptions.ResolveSecurityToken` or
`VerifyOptions.ResolveSecurityToken` returns, and fails with
`ErrSecurityTokenUnavailable` without one. A SAML key identifier
(`SAMLAssertionID`, `SAMLID`) names the assertion in the message whose
`AssertionID` or `ID` it holds, and that assertion is digested; an ID
carried twice is `ErrAmbiguousID`, an assertion not in the message
`ErrSecurityTokenUnavailable`. Any other key identifier, such as
`EncryptedKeySHA1` or a Kerberos one, is `ErrUnsupportedKeyInfo`: the
transform cannot reproduce that token.
`Coverage.SignedTokens` reports each token covered this way; the reference
itself is not covered and not reported. To protect both, sign the reference
twice, with and without the transform.

### Receiving

```go
sec, err := wss.FindHeader(doc, xmlsec.NSSOAP12, "") // nil if there is none
err = wss.CheckUniqueIDs(doc)                        // before resolving anything
tsEl, err := wss.FindTimestamp(sec)                  // nil if there is none
```

`FindHeader` refuses two headers for the same actor or role (R3206, R3210),
`FindTimestamp` two timestamps (R3227), and `CheckUniqueIDs` any ID value
carried twice across `wsu:Id`, `xml:id` and the attributes you name (R3204),
each with `ErrMalformed` or `ErrAmbiguousID`.

`VerifyOptions.StrictBSP` refuses, before any cryptographic work, a
signature the Basic Security Profile forbids: `ds:SignedInfo` not under
Exclusive C14N (R5404), `HMACOutputLength` (R5401), a `ds:KeyInfo` other
than one valid `wsse:SecurityTokenReference` (R5402, R5417), a `ds:Manifest`
or `xenc:EncryptedData` in the signature (R5403, R5440), a reference without
transforms (R5416, R5411), with a transform outside Exclusive C14N, XPath
Filter 2.0, the STR Dereference Transform, enveloped-signature and the SwA
signature transforms (R5423) or ending in another (R5412), a `cid:`
reference not beginning with an SwA transform (R6101), and a reference into
the signature's own `ds:Object` (R3102). It implies
`StrictSecurityTokenReference`.

### Signature confirmation

A responder confirms every signature of the request (§8.5); the initiator
keeps its own signature values and checks the response:

```go
// Responder: one confirmation per request signature, or one with no value.
values, err := wss.SignatureValues(requestSecurityHeader)
for _, v := range values {
	id, err := hdr.AddSignatureConfirmation(v) // sign it by id
}
if len(values) == 0 {
	id, err := hdr.AddSignatureConfirmation(nil)
}

// Initiator, after dsig.Verify on the response, with every confirmation
// in its Coverage:
err = wss.CheckSignatureConfirmations(responseSecurityHeader, sentValues)
```

`CheckSignatureConfirmations` compares in constant time and refuses a
missing confirmation, a value that confirms no request signature, a request
signature left unconfirmed, and a `Value` present or absent against whether
the request was signed, with `ErrSignatureInvalid`.

### Reproducible output

An ID is inside the signed octets, so a minted one makes every run
different. For a golden file, or a differential against another
implementation, supply every ID and the clock, and the output is
byte-identical from run to run with RSA (PKCS#1 v1.5 is deterministic;
ECDSA is not):

```go
msgID, err := wss.AssignIDWith(doc, messaging, "msg-1")
bodyID, err := wss.AssignIDWith(doc, body, "body-1")
tsID, err := hdr.AddTimestampWithID(fixedNow, 5*time.Minute, "ts-1")
tokID, err := hdr.AddBinarySecurityTokenWithID(cert, nil, xmlsec.BSTValueTypeX509v3, "bst-1")
sig, err := dsig.Sign(doc, key, dsig.SignOptions{
    // ... references to msgID, bodyID, tsID and attachments ...
    KeyInfo:          dsig.KeyInfoSecurityTokenReference,
    SecurityTokenID:  tokID,
    SignatureID:      "sig-1",
    SignedInfoID:     "si-1",
    SignatureValueID: "sv-1",
    KeyInfoID:        "ki-1",
})
```

`AddSignatureConfirmationWithID` does the same for a confirmation, and
`xenc.EncryptOptions.DataID` for an `EncryptedHeader`. Each `…WithID` takes an
NCName not already in the document, and refuses anything else; an element
that already has an ID keeps it. Session keys, IVs and ECDSA signatures stay
random, so only signed-only output is reproducible end to end.

### Faults

SOAP Message Security §12 names the faults a receiver returns.
`wss.FaultCode(err)` maps an error to one, as a `wsse`-prefixed QName; for
SOAP 1.2 the Code is `env:Sender` with the QName as Subcode.

| Error | Fault |
|---|---|
| `ErrMessageExpired` | `wsse:MessageExpired` |
| `ErrSecurityTokenUnavailable` (a reference to a token not there, a resolver without the certificate) | `wsse:SecurityTokenUnavailable` |
| `ErrInvalidSecurityToken` (a token whose content is not what its `ValueType` says) | `wsse:InvalidSecurityToken` |
| `ErrUnsupportedAlgorithm`, `ErrAlgorithmNotAllowed`, `ErrTransformRefused` | `wsse:UnsupportedAlgorithm` |
| `ErrUnsupportedKeyInfo` | `wsse:UnsupportedSecurityToken` |
| `ErrUntrusted` | `wsse:FailedAuthentication` |
| `ErrDigestMismatch`, `ErrSignatureInvalid`, `ErrDecryptionFailed` (every key-unwrap and decryption failure, one message whatever the cause) | `wsse:FailedCheck` |
| anything else: `ErrMalformed`, `ErrAmbiguousID`, `ErrIDNotFound`, `ErrUnverifiable`, `ErrLimitExceeded`, `ErrAttachmentNotFound` | `wsse:InvalidSecurity` |

The first row that matches wins; the new sentinels wrap alongside the old
ones, so `errors.Is(err, xmlsec.ErrMalformed)` still holds for a malformed
token. The mapping names a class of check, never a step of it, so it is no
oracle; still, §12 lets a receiver return no fault or one generic fault, the
safer choice facing an unauthenticated sender. Never put the error's text in
the fault string.

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
// Then confirm cov.CoversNodes(assertion) for the assertion you will read.
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
`SigDSASHA256` (with (2048, 256) or (3072, 256) DSA keys), `SigECDSASHA1`,
`SigHMACSHA1` and `DigestSHA1`. `Sign` never produces them. The HMAC-SHA2
constants, `SigHMACSHA224` included, are also outside the default set, and
verify only when listed and keyed with `HMACKey`; `Sign` produces them with
`SignOptions.HMACKey`. The SHA-224 algorithms, `SigRSASHA224`,
`SigECDSASHA224` and `DigestSHA224`, are outside the default sets too, but not
weak: `Sign` produces them when asked, and a verifier accepts them when it
names them.

To pin a sender known by a raw key rather than a certificate, set
`VerifyOptions.PublicKey` instead of `Certificate`; setting both is an
error. With a key pinned, a `KeyInfo` form this library does not accept is
ignored (`KeyInfoForm` is then `KeyInfoNone`), and so is a
`ds:X509Certificate` Go cannot parse (§3.2.2: the key comes from `KeyInfo`
or an external source); a malformed or ambiguous one is still refused.
Unpinned, an unparsable certificate is `ErrMalformed`. When signing, `KeyInfoKeyValue` and
`KeyInfoDEREncodedKeyValue` emit the signer's key without a certificate.

### KeyInfo forms

What `Sign` emits, by `SignOptions.KeyInfo`:

| Form | Emits | Options |
|---|---|---|
| `KeyInfoX509Data` | `ds:X509Data` with the signing certificate | `Chain` adds certificates after it, towards a trust anchor; `X509Descriptors`, a list of `dsig.X509Descriptor` (`X509IssuerSerial`, `X509SKI`, `X509SubjectName`, `X509Digest`, SHA-256), adds those elements for the signing certificate before it |
| `KeyInfoX509Descriptors` | `ds:X509Data` with only the `X509Descriptors` | the verifier must hold the certificate |
| `KeyInfoKeyValue`, `KeyInfoDEREncodedKeyValue` | the raw public key | |
| `KeyInfoKeyName` | `ds:KeyName` alone | `KeyName` is required |
| `KeyInfoReference` | `dsig11:KeyInfoReference` | `KeyInfoReferenceURI`: `"#id"` of a `ds:KeyInfo` you place in the document, or an absolute URI |
| `KeyInfoSecurityTokenReference` | a `wsse:SecurityTokenReference` | `SecurityTokenID` |

`KeyName`, when set, is emitted first beside any form but `KeyInfoNone`.
The signing certificate must be the one leaf of itself and `Chain`;
`Chain` may hold other certificates for its key, such as a re-issue.

`SignOptions.KeyInfo`'s zero value, `KeyInfoNone`, emits no `ds:KeyInfo`:
the verifier must already hold the key.

What `Verify` accepts, with at most one `ds:KeyName` beside, reported in
`Coverage.KeyName`:

* `ds:X509Data`, in one or several elements: up to 16 certificates, of which
  exactly one issued none of the others, where certificates for the same
  public key, such as a certificate and its re-issue, count as one (§4.5.4).
  That leaf is the signing certificate, the first of them in document order
  when several carry its key; the rest are `Coverage.Intermediates`. Leaves
  for different keys are refused with `ErrUnsupportedKeyInfo`. Each `ds:X509CRL`
  is in `Coverage.CRLs`, none of them checked. An `X509IssuerSerial`,
  `X509SKI`, `X509SubjectName` or `dsig11:X509Digest` beside the
  certificates selects nothing and is ignored: real signers renew a
  certificate and leave a stale one. With `StrictX509Data` each must
  describe one of the certificates, or verification fails with
  `ErrUnsupportedKeyInfo`; names compare as RFC 4514 distinguished names,
  and an `X509Digest` algorithm must pass `AllowedDigestAlgorithms`.
  Children in other namespaces are ignored.
* A raw key: `ds:KeyValue` or `dsig11:DEREncodedKeyValue`, DSA only for an
  allowed DSA signature.
* A `ds:RetrievalMethod` to `"#id"`, without transforms, whose `Type` is
  `X509Data`, `RSAKeyValue`, `DSAKeyValue`, `ECKeyValue` or
  `DEREncodedKeyValue` and names an element of that type; without a `Type`,
  which is optional (§4.5.3), the element named must be one of those; or,
  through `ResolveKeyInfoURI`, to an absolute URI of `Type`
  `rawX509Certificate`, which needs the `Type`.
* A `dsig11:KeyInfoReference` to a `ds:KeyInfo` in the same document or,
  through `ResolveKeyInfoURI`, in another.
* A `wsse:SecurityTokenReference`.

A reference is followed one hop: a `RetrievalMethod` or `KeyInfoReference`
in what one reaches is refused. Three opt-in resolvers cover what the
message only names:

| Option | Called for |
|---|---|
| `ResolveKeyName func(name string) (*x509.Certificate, crypto.PublicKey, error)` | a `ds:KeyName` alone; return a certificate or a raw key. `KeyInfoForm` is then `KeyInfoKeyName` |
| `ResolveX509 func(dsig.X509Identifier) (*x509.Certificate, error)` | `ds:X509Data` without a certificate; the identifier carries the issuer and serial, SKI, subject name and digest, and the certificate returned must match them. `KeyInfoForm` is then `KeyInfoX509Descriptors` |
| `ResolveKeyInfoURI xmlsec.URIResolver` | a `KeyInfoReference`, or a `RetrievalMethod` of `Type` `rawX509Certificate`, to an absolute URI; an error is `ErrDereference` |

All three run before the signature is verified, on names and URIs the
unauthenticated message chose, though only after every algorithm has passed
the allow-lists; `TrustKey` then judges what they return. Look names up among
keys you already hold, and serve URIs from a fixed set: see
[security.md](security.md#key-resolvers-run-before-authentication). None is
called when a key is pinned.

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
| `StrictX509Data` | Refuse an `X509IssuerSerial`, `X509SKI`, `X509SubjectName` or `dsig11:X509Digest` beside the carried certificates that describes none of them (XML Signature §4.5.4). Off by default: a descriptor beside a certificate selects nothing, and real signers leave stale ones after renewing. |
| `ResolveKeyName`, `ResolveX509`, `ResolveKeyInfoURI` | Resolve a key the message names without carrying it; see [KeyInfo forms](#keyinfo-forms). |

Then check `Coverage`, every time. The three `Covers` methods of a nil
`Coverage`, which a failed `Verify` returns, report false:

| Field | Check |
|---|---|
| `CoversNodes(elements...)` | the elements you will read were signed, compared by identity: prefer it |
| `Covers(ids...)` / `SignedElements` | the IDs were signed; safe only when you then locate each element by that ID with `wss.FindByID`, since a wrapped document satisfies an ID check |
| `CoversAttachments(ids...)` | every attachment is signed |
| `WholeDocumentSigned` | set for an enveloped signature |
| `ExternalURIs` | the absolute URIs your `ResolveURI` supplied; what it returned is what was signed |
| `KeyInfoForm` | the key was described the way your profile requires |
| `Certificate` | **you** establish that it is trusted |
| `PublicKey` | the key the signature was verified with; `Certificate` is nil when it was a raw key |
| `Intermediates`, `CRLs` | the other certificates and the CRLs of `ds:X509Data`, unverified, for **your** path building and revocation checks |
| `KeyName` | the `ds:KeyName` received; unauthenticated unless a reference signs `ds:KeyInfo` |
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
| `ErrDereference` | your `ResolveURI` or `ResolveKeyInfoURI` failed; wraps its error |
| `ErrUnsupportedKeyInfo` | no usable key in `ds:KeyInfo`: a form this library does not accept, an `X509Data` descriptor that describes none of its certificates (under `StrictX509Data`), or a key resolver's refusal, which it wraps |

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
if err != nil {
    return err
}
defer clear(ek.SessionKey)
// For a second recipient, wrap the same key: set opts.SessionKey =
// ek.SessionKey and opts.Recipient, and call GenerateEncryptedKey again.

ciphertext, ed, err := xenc.EncryptAttachment(att, ek.SessionKey, xmlsec.TransformAttachmentContentOnly, opts)
// Replace the MIME body with ciphertext, Content-Type application/octet-stream,
// place ek.Element and ed in the security header.
```

Pass `xmlsec.TransformAttachmentComplete` instead to encrypt the listed MIME
headers with the body. Then keep Content-ID on the part and drop the other
listed headers. With Attachment-Content-Only, a part without a Content-Type
gets `MimeType="text/plain; charset=us-ascii"`, the Content-Type such a part
has (SwA profile sections 5.4.1 and 5.5.2).

`DecryptAttachment` requires the `CipherReference` to carry exactly the
Attachment-Ciphertext-Transform (SwA profile section 5.5.1), as
`EncryptAttachment` writes it. For Attachment-Complete, decrypted MIME
headers that do not parse, or include one the profile does not list or one
twice, are `ErrDecryptionFailed`, the same error as a wrong key or bad CBC
padding: a detailed error about the plaintext would be an oracle.

The MGF is emitted explicitly. Omitting it means SHA-1 by specification
default, so `DecryptEncryptedKey` refuses an `EncryptedKey` without one.
`xmlsec.MGF1SHA224` is produced when you name it, and accepted only when
`AllowedMGFAlgorithms` names it. `DigestAlgorithm` may be
`xmlsec.DigestSHA384XMLEnc`, XML Encryption's own SHA-384 identifier
(section 5.8.3), as well as the SHA-2 `Digest*` constants.

An option that has no effect on what is produced, or contradicts another,
is refused rather than ignored: `GenerateEncryptedKey` refuses more than
one of `Recipient`, `RecipientDH`, `KeyEncryptionKey` and `Password`;
`MGFAlgorithm` and `OAEPParams` except with RSA-OAEP; `KeyEncryptionKey`,
`Password` and `RecipientDH` with RSA-OAEP; `DigestAlgorithm` and
`KeyAgreementAlgorithm` with a `KeyEncryptionKey` or `Password`;
`RecipientKeyName` without `RecipientDH`; and `MasterKey` and
`DirectKeyAgreement`, which make no `EncryptedKey`. Every function refuses
`PBKDF2Iterations` without `Password` or outside 1000 to 10,000,000. The
`EncryptedData` fields, such as `DataID`, are ignored by
`GenerateEncryptedKey`, so one options value serves both.

What to encrypt:

| Function | Encrypts | Type |
|---|---|---|
| `xenc.EncryptElement(doc, el, key, opts)` | an element, in place of itself | `xenc#Element` |
| `xenc.EncryptContent(doc, el, key, opts)` | an element's content, such as the SOAP Body's | `xenc#Content` |
| `xenc.EncryptHeader(doc, block, security, key, opts)` | a SOAP header block, as a `wsse11:EncryptedHeader` carrying the Security header's `mustUnderstand` and `actor`/`role`; without `DataID` the `EncryptedData` gets a random `Id` (BSP R5624) | `xenc#Element` |
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
  `priv, err := ecKey.ECDH()` and `xenc.DecryptAgreedKey(ekElement, priv,
  xenc.DecryptOptions{})`, `ekElement` being the received `EncryptedKey`.
- **AES key wrap** with a key you share: set `KeyEncryptionKey`, and receive
  with `xenc.UnwrapEncryptedKey`.
- **Finite-field Diffie-Hellman** and **a password (PBKDF2)**: OPTIONAL, and
  opt-in on receipt; see below.

Receiving:

```go
edKey, err := xenc.FindEncryptedKey(edElement) // inline, RetrievalMethod, KeyName, SecurityTokenReference, or ReferenceList
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
`EncryptedData` that is the document element. Another `Type` is refused
before decryption; a plaintext that does not parse or has the wrong shape is
`ErrDecryptionFailed`, like a wrong key, since with CBC telling the two apart
is an oracle. For a `wsse11:EncryptedHeader` use `DecryptHeader` (below),
which replaces the whole header.
`DecryptData` also follows a same-document `CipherReference` with the base64
transform. `EncryptionMethod` is read strictly: a child the algorithm does not
permit, or a `KeySize` inconsistent with it, is refused.

### Symmetric binding

WSS4J's symmetric binding turns the references round (SOAP Message Security
1.1.1 §7.7, §9.4.1): the `EncryptedKey` carries no `ReferenceList`; a
standalone `ReferenceList` in the header names the `EncryptedData`, and each
`EncryptedData` names the key in its own `ds:KeyInfo`, by a
`SecurityTokenReference` to the `EncryptedKey`'s `Id` (BSP R5629, R5426):

```go
ek, err := xenc.GenerateEncryptedKey(opts)
ekID, err := wss.AssignID(doc, ek.Element)         // an unqualified Id
err = ek.SetKeyInfo(recipientSTR)                  // which private key unwraps it
opts.DataKeyInfo, err = wss.NewSecurityTokenReference(doc, ekID,
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey") // with TokenType (R3069)
list, err := wss.NewReferenceList("ED-body", "ED-header")
err = hdr.Prepend(list)
err = hdr.Prepend(ek.Element)                      // ahead of the list
opts.DataID = "ED-body"
out, err := xenc.EncryptContent(doc, body, ek.SessionKey, opts)
// parse out, then with opts.DataID = "ED-header":
// xenc.EncryptHeader(doc2, block, security, ek.SessionKey, opts)
```

`DataKeyInfo` is the child of the `ds:KeyInfo`, which the library wraps
around a copy of it after the `EncryptionMethod`, for every `Encrypt`
function; one options value serves every part. It is refused together with
`MasterKey`, `DirectKeyAgreement` or a `Password` with no session key, which
put their own `DerivedKey` or `AgreementMethod` in that `ds:KeyInfo`.

Receiving either shape:

```go
eds, err := xenc.ReferencedData(referenceList)  // the header's list, in order
for _, ed := range eds {
    ekEl, err := xenc.FindEncryptedKey(ed)      // follows the SecurityTokenReference one hop
    key, err := xenc.DecryptEncryptedKey(ekEl, decrypter, allow)
    if ed.Parent.IsElement(xmlsec.NSWSSE11, "EncryptedHeader") {
        out, err := xenc.DecryptHeader(doc, ed.Parent, key, allow) // the document, header restored
    } else {
        plaintext, err := xenc.DecryptData(ed, key, allow)
    }
}
```

`xenc.DecryptHeader` (§9.4.4) requires exactly one `EncryptedData` in the
`EncryptedHeader` (R3230), decrypts it, parses the plaintext in the
`EncryptedHeader`'s namespace context with `xmlsec.Parse` (no DOCTYPE), and
returns the whole document, canonical, with the header block in its place;
`doc` is not modified. A plaintext that is not exactly one element is
`ErrDecryptionFailed`, like a wrong key. It shares `DecryptAndReplace`'s parsing.

`DecryptOptions.StrictBSP` checks what the Basic Security Profile says about
the encryption elements received before any key is used: no `Type`,
`MimeType`, `Encoding` or `Recipient` on an `EncryptedKey`; every `KeyInfo`
exactly one `SecurityTokenReference`; no `EncryptedData` directly in the SOAP
Header; a `KeyInfo` on every `EncryptedData` no `EncryptedKey` names.
Refusals are `ErrMalformed`, in every Decrypt, Unwrap and Derive function.
It refuses key agreement, PBKDF2 and derived keys, whose `KeyInfo` the
profile does not allow, and leaves algorithms to the allow-lists.

### Finite-field Diffie-Hellman and passwords

XML Encryption 1.1's OPTIONAL key establishment, none of it in a default
allow-list. Diffie-Hellman keys are `xenc.DHPublicKey` and
`xenc.DHPrivateKey` (`math/big` P, Q, G, Y and X), in a group of 2048 to
8192 bits (`xenc.MinDHBits` to `MaxDHBits`) with its subgroup order Q, such as RFC 7919 ffdhe2048, whose Q is
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

key, err := xenc.DecryptAgreedKeyDH(ek.Element, recipient, xenc.DecryptOptions{
    AllowedKeyAgreementAlgorithms: []string{xmlsec.KeyAgreementDHES},
})
```

The receiver checks that the originator's public value lies in its own
group's order-Q subgroup, and refuses any other group.

A password derives the KEK by PBKDF2 with HMAC-SHA256, a fresh 16-octet salt
and 600,000 iterations (`xenc.DefaultPBKDF2Iterations`) unless
`PBKDF2Iterations` says otherwise; the
parameters travel in an `xenc11:DerivedKey`:

```go
ek, err := xenc.GenerateEncryptedKey(xenc.EncryptOptions{
    DataAlgorithm:         xmlsec.EncAES256GCM,
    KeyTransportAlgorithm: xmlsec.KeyWrapAES256,
    Password:              password,
})

key, err := xenc.UnwrapEncryptedKeyPassword(ek.Element, password, xenc.DecryptOptions{
    AllowedKeyDerivationAlgorithms: []string{xmlsec.KeyDerivationPBKDF2},
})
```

A received iteration count over `xenc.MaxPBKDF2Iterations` (10,000,000) is
refused before any work, and one under `MinPBKDF2Iterations` (1000) as weak. The HMAC-SHA1 PRF is
accepted only when `AllowedPRFAlgorithms` names `xmlsec.SigHMACSHA1`.
Naming `xmlsec.KeyDerivationPBKDF2` also lets `DecryptAgreedKey` and
`DecryptAgreedKeyDH` accept PBKDF2 as a key agreement's KDF, with the shared
secret as the password.

### Key chains, derived keys and direct key agreement

The other `ds:KeyInfo` forms of sections 3.5 and 5.6, each found the same
ways: a child of the `KeyInfo`, a same-document `ds:RetrievalMethod` of
`Type` `xenc.TypeEncryptedKey` or `xenc.TypeDerivedKey` (or
`http://www.w3.org/2009/xmlenc11#DerivedKey`, which section 3.5.3 gives
instead; several naming one element are accepted, naming two is
`xmlsec.ErrAmbiguousID`), a
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
A `DerivedKey` without `KeyDerivationMethod` is derived by the one you
pass, with its parameters, as `DecryptOptions.ImpliedKeyDerivationMethod`.
`ConcatKDFParams` are bit strings (section 5.4.1), concatenated unpadded;
when their total is not a whole number of octets, which no hash over octets
can take, they are refused.

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

priv, err := ecKey.ECDH() // ecKey is the recipient's *ecdsa.PrivateKey
key, err := xenc.DecryptAgreedDataKey(ed, priv, xenc.DecryptOptions{})
// finite-field: xenc.DecryptAgreedDataKeyDH(ed, dhPriv, xenc.DecryptOptions{...})
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

An `xenc:CipherReference` without a `URI` attribute is refused
(`ErrMalformed`): the schema requires it, and only `URI=""` names the whole
document.

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
