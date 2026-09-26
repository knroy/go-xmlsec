# Usage

Every call names its algorithms. There are no defaults: two document families
that commonly meet in one system — WS-Security messages and enveloped
metadata documents — need different canonicalization, and a default would
produce a signature that looks right and that no peer accepts.

| Context | Canonicalization |
|---|---|
| WS-Security, AS4: references and `ds:SignedInfo` | `c14n.Exclusive10` |
| Enveloped document signatures such as SMP metadata | `c14n.Inclusive10` |

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

## WS-Security signature

`dsig.Sign` returns a detached `ds:Signature` for you to place, and does not
modify the document. A detached signature's `ds:SignedInfo` is canonicalized
before you place it, and only exclusive canonicalization is independent of
where it ends up, so a detached signature needs exclusive canonicalization.
To use any other, set `SignOptions.Parent` to the element the signature
belongs in: `Sign` then appends it there first and computes it in place,
leaves it there, and leaves the document unchanged if it fails. (The WS-I
Basic Security Profile requires exclusive canonicalization for WS-Security
anyway.)

1. Give every signed element an ID: `wss.AssignID(doc, el)`.
2. Create the header and the token: `wss.NewHeader`, then
   `hdr.AddBinarySecurityToken`. The token must be in the document before
   signing, since the `SecurityTokenReference` points at it.
3. `dsig.Sign` with `KeyInfo: dsig.KeyInfoSecurityTokenReference` and
   `SecurityTokenID` set to the token's ID.
4. `hdr.Append(sig)`.

Reference forms:

| URI | Transforms | Covers |
|---|---|---|
| `"#id"` | a canonicalization, last | the element with that `wsu:Id` or `xml:id`, or an attribute named in `IDAttributes` |
| `"cid:..."` | `TransformAttachmentContentSignature` | the attachment content, canonicalized: Exclusive C14N for XML types, CRLF line endings for other text, the octets as they are otherwise |
| `"cid:..."` | `TransformAttachmentCompleteSignature` | as above, preceded by the canonical Content-Description, -Disposition, -ID, -Location and -Type headers |
| `""` | `TransformEnvelopedSignature`, then a canonicalization | the whole document minus the enclosing signature |

When signing, a same-document reference with no transforms, or whose last
transform leaves a node set, is refused: this library never produces a
signature that relies on an implicit canonicalization. When verifying, such a
reference is completed with Canonical XML 1.0, as XML Signature section
4.4.3.2 requires, because most signing software relies on exactly that; the
implied algorithm is checked against `AllowedCanonicalizationAlgorithms` like
a named one.

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
signing and verifying. `wss.FindByIDAttributes` does the same lookup
directly. `SecurityTokenID` and `SecurityTokenReference` resolution still use
`wsu:Id` and `xml:id` only.

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

Pass exactly the algorithms your profile permits. An empty list means every
algorithm this module implements, which is a downgrade surface.

To pin a sender known by a raw key rather than a certificate, set
`VerifyOptions.PublicKey` instead of `Certificate`; setting both is an
error. A pinned key replaces `KeyInfo` and is not compared with it, but an
unsupported or malformed `KeyInfo` is still refused. When signing,
`KeyInfoKeyValue` and `KeyInfoDEREncodedKeyValue` emit the signer's key
without a certificate.

Two more options narrow what is accepted:

| Option | Effect |
|---|---|
| `TrustKey func(cert *x509.Certificate, key crypto.PublicKey) error` | Called with the signer's key, and its certificate when there is one, before any cryptographic or digest work; an error stops verification with `ErrUntrusted`. Use it when you cannot pin one certificate but know which you accept: a refused sender costs nothing to process. |
| `RequireExplicitCanonicalization` | Refuse a reference that relies on the Canonical XML 1.0 implied by XML-DSig 4.4.3.2, even when that algorithm is in the allow-list. Off by default, because most signers rely on it. |

Then check `Coverage`, every time:

| Field | Check |
|---|---|
| `Covers(ids...)` / `SignedElements` | every element your profile requires is signed; compare identity, not just ID, when you locate elements by position |
| `CoversAttachments(ids...)` | every attachment is signed |
| `WholeDocumentSigned` | set for an enveloped signature |
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
| `ErrTransformRefused` | XSLT or XPath |

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

ciphertext, ed, err := xenc.EncryptAttachment(att, ek.SessionKey, xmlsec.TransformAttachmentContentOnly, opts)
// Replace the MIME body with ciphertext, Content-Type application/octet-stream,
// place ek.Element and ed in the security header.
```

Pass `xmlsec.TransformAttachmentComplete` instead to encrypt the listed MIME
headers with the body. Then keep Content-ID on the part and drop the other
listed headers.

```go
```

The MGF is emitted explicitly. Omitting it means SHA-1 by specification
default, so `DecryptEncryptedKey` refuses an `EncryptedKey` without one.

A WS-Security receiver such as WSS4J finds the session key through the
`EncryptedKey` in the header: its `ds:KeyInfo` names the recipient's key, and
its `xenc:ReferenceList` names each `EncryptedData` it decrypts. Compose them
as a sender does:

```go
tokenID, err := hdr.AddBinarySecurityToken(recipientCert, nil, xmlsec.BSTValueTypeX509v3)
str, err := wss.NewSecurityTokenReference(doc, tokenID, xmlsec.BSTValueTypeX509v3)

opts.DataID = "ED-1"                  // the Id the EncryptedData will carry
ek, err := xenc.GenerateEncryptedKey(opts)
err = ek.SetKeyInfo(str)              // which key unwraps it
ek.AddDataReference(opts.DataID)      // what it decrypts
err = hdr.Append(ek.Element)
encrypted, err := xenc.EncryptElement(doc, payload, ek.SessionKey, opts)
```

This is exactly what `TestWSS4JDecryptsOurEncryption` sends to WSS4J. A
peer that instead looks for the key inside `EncryptedData/ds:KeyInfo`, as
`xmlsec1` does, needs the `EncryptedKey` placed there.

Receiving:

```go
key, err := xenc.DecryptEncryptedKey(ekElement, decrypter,
    []string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
att, err := xenc.DecryptAttachment(edElement, mimeBody, key, []string{xmlsec.EncAES128GCM})
// Replace the part's body with att.Body, and its headers of the same names
// with att.MIMEHeaders.
```

`xenc.EncryptElement` encrypts an element in place of itself and returns the
document octets; `xenc.DecryptData` returns the element's octets, which parse
on their own because the plaintext declares every namespace in scope.

## Order within `wsse:Security`

1. `wsse:BinarySecurityToken`
2. `ds:Signature`
3. `xenc:EncryptedKey`
4. `xenc:EncryptedData`

A token must precede the signature that references it.
