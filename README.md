# go-xmlsec

**XML Signature, XML Encryption and WS-Security in pure Go.** No cgo, no
libxml2, no `encoding/xml`: parsing and canonicalization come from
[go-xml](https://github.com/knroy/go-xml), and this module never serializes
anything it digests except through `go-xml/c14n`.

```
go get github.com/knroy/go-xmlsec
```

Requires Go 1.26 or later.

## Status: v0, not yet independently validated

Read this before depending on it.

| Evidence | Status |
|---|---|
| Unit and conformance tests | 63 test and fuzz functions, run on Linux, macOS and Windows in CI; 100% statement coverage, enforced by CI |
| Negative corpus: modified element, modified attachment, relocated element, duplicated ID, algorithm outside allow-list, truncated signature | Yes, each a named test |
| Differential against `xmlsec1` 1.3 | **Yes**, in CI: it verifies our enveloped and detached signatures (RSA, ECDSA; inclusive, exclusive) and decrypts our AES-GCM / RSA-OAEP encryption, and we do the same for its output |
| Differential against Apache Santuario | **Not yet built** |
| Signature byte-equality with phase4 (Gate 2) | **Not yet built** |
| Fuzzing | Three targets on the parse-and-verify and decrypt paths, nightly at one hour each |
| Canonicalization conformance (Gate 1) | Owned upstream by `go-xml/c14n` v1.4.0, which reports differential testing against `xmllint` and `xmlsec1`; the Santuario differential and real-message corpus are still open there |

One independent implementation accepts what this module produces, and the
spec asks for two before anything is called validated. That is why it is v0. See [docs/testing.md](docs/testing.md) for exactly what
runs and [docs/todo.md](docs/todo.md) for what stands between here and v1.

## Sign and verify

A WS-Security signature over two header elements and an attachment:

```go
tree, _ := xmlsec.Parse(envelope)
doc := tree.Root

bodyID, _ := wss.AssignID(doc, body)
hdr, _ := wss.NewHeader(doc, wss.NSSOAP12, "", true)
tokenID, _ := hdr.AddBinarySecurityToken(key.Certificate, nil, xmlsec.BSTValueTypeX509v3)

exc := []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}
sig, err := dsig.Sign(doc, key, dsig.SignOptions{
    SignatureAlgorithm:        xmlsec.SigRSASHA256,
    CanonicalizationAlgorithm: string(c14n.Exclusive10),
    References: []dsig.Reference{
        {URI: "#" + bodyID, Transforms: exc, DigestAlgorithm: xmlsec.DigestSHA256},
        {URI: "cid:att-1@example.com", DigestAlgorithm: xmlsec.DigestSHA256,
            Transforms: []dsig.TransformSpec{{Algorithm: xmlsec.TransformAttachmentContentOnly}}},
    },
    KeyInfo:         dsig.KeyInfoSecurityTokenReference,
    SecurityTokenID: tokenID,
    Attachments:     atts,
})
hdr.Append(sig)
```

Verify, and **check what was signed**:

```go
tree, _ := xmlsec.Parse(received)
cov, err := dsig.Verify(tree.Root, sigElement, dsig.VerifyOptions{
    AllowedSignatureAlgorithms:        []string{xmlsec.SigRSASHA256},
    AllowedDigestAlgorithms:           []string{xmlsec.DigestSHA256},
    AllowedCanonicalizationAlgorithms: []string{string(c14n.Exclusive10)},
    Attachments:                       atts,
})
if err != nil || !cov.Covers(bodyID) || !cov.CoversAttachments("att-1@example.com") {
    // reject
}
// cov.Certificate is NOT trusted by this library. Establish that yourself.
```

A nil error means the signature is valid over the nodes in `Coverage` and
nothing more. It says nothing about whether the certificate is trusted, and
nothing about elements `Coverage` does not list. That is how XML Signature
Wrapping works; [docs/security.md](docs/security.md) explains it.

More, including enveloped signatures and encryption, in
[docs/usage.md](docs/usage.md).

## What it refuses

SHA-1 in every role, the `rsa-oaep-mgf1p` key transport, XSLT and XPath
transforms, DOCTYPEs, any network or filesystem access, and trust decisions.
Each is deliberate; [docs/security.md](docs/security.md#deliberate-refusals)
gives the reason.

## Documentation

[docs/](docs/README.md) · [CHANGELOG.md](CHANGELOG.md) ·
[SECURITY.md](SECURITY.md) · [RELEASE.md](RELEASE.md)

## License

MIT. See [LICENSE](LICENSE).
