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

## WS-Security signature

`dsig.Sign` returns a detached `ds:Signature` for you to place, and does not
modify the document. Its `ds:SignedInfo` canonicalization must be exclusive:
it is canonicalized before you place the signature, and only exclusive
canonicalization is independent of where it ends up. `Sign` refuses an
inclusive one.

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
| `"#id"` | a canonicalization, last | the element with that `wsu:Id` or `xml:id` |
| `"cid:..."` | `TransformAttachmentContentOnly` | the attachment body octets, exactly as on the wire |
| `""` | `TransformEnvelopedSignature`, then a canonicalization | the whole document minus the enclosing signature |

When signing, a same-document reference with no transforms, or whose last
transform leaves a node set, is refused: this library never produces a
signature that relies on an implicit canonicalization. When verifying, such a
reference is completed with Canonical XML 1.0, as XML Signature section
4.4.3.2 requires, because most signing software relies on exactly that; the
implied algorithm is checked against `AllowedCanonicalizationAlgorithms` like
a named one.

`Attachment-Content-Only` is the identity on `Attachment.Body`. The digest
covers the octets as transmitted — compressed, if the part is compressed.
Never decompress before verifying.

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

Then check `Coverage`, every time:

| Field | Check |
|---|---|
| `Covers(ids...)` / `SignedElements` | every element your profile requires is signed; compare identity, not just ID, when you locate elements by position |
| `CoversAttachments(ids...)` | every attachment is signed |
| `WholeDocumentSigned` | set for an enveloped signature |
| `KeyInfoForm` | the key was described the way your profile requires |
| `Certificate` | **you** establish that it is trusted |
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

The MGF is emitted explicitly. Omitting it means SHA-1 by specification
default, so `DecryptEncryptedKey` refuses an `EncryptedKey` without one.

`GenerateEncryptedKey` emits no `ds:KeyInfo` naming the recipient key, and no
`xenc:ReferenceList`; add what your profile requires. See
[todo.md](todo.md). A peer that locates the session key through
`EncryptedData/ds:KeyInfo`, as `xmlsec1` does, needs the `EncryptedKey`
placed there.

Receiving:

```go
key, err := xenc.DecryptEncryptedKey(ekElement, decrypter,
    []string{xmlsec.KeyTransportRSAOAEP}, []string{xmlsec.MGF1SHA256}, []string{xmlsec.DigestSHA256})
plain, err := xenc.DecryptAttachment(edElement, mimeBody, key, []string{xmlsec.EncAES128GCM})
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
