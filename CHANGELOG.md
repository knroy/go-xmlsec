# Changelog

Notable changes, newest first. Versions follow [semantic
versioning](https://semver.org): within a major version no exported name is
removed or changed. See [RELEASE.md](RELEASE.md) for the compatibility
promise and how a release is cut.

## v2.2.0 — 2026-11-13

### Fixed — security

From a full security audit of v2.1.0 (dc5b096). Every fix stays within XML
Signature 1.1 and XML Encryption 1.1: conforming signatures still verify and
conforming ciphertext still decrypts. What changes is what `Coverage`
reports, and new limits on how much work one message can force. The W3C
vectors, the golden hashes and the xmlsec1, Santuario and WSS4J interop
suite pass unchanged.

| Change | Problem → solution | Commit |
|---|---|---|
| `Coverage` reported a signature's own `ds:Object`, `ds:KeyInfo` or `ds:Manifest` as signed when the enveloped-signature transform had removed all of it | A reference to an element inside the signature, through enveloped-signature, digests nothing of it (§6.6.4), yet the element was listed in `SignedElements`, so it could be rewritten with the signature still valid. `VerifyManifest` trusted that entry. The exemption for dropping the signature's nodes now applies only when the signature lies inside the target, on the enveloped-signature, XPath and Filter 2.0 paths. Such a reference still verifies but covers nothing, and `VerifyManifest` refuses a Manifest reached that way. | [`5489f85`][5489f85] |
| `Coverage` reported an element as signed when the base64 transform digested only its text | Over a node set the base64 transform digests text alone (§6.6.2), so attributes, child elements, comments and PIs of a "covered" element could be forged. Such a reference now appears in `Coverage.References` only, as an XSLT one does. | [`5489f85`][5489f85] |
| An encoded MIME header could forge another in an Attachment-Complete signature | The canonical header block was checked for line breaks before RFC 2047 and RFC 2231 decoding, not after, so a `Content-Description` decoding to `\r\nContent-Disposition: ...` digested as that header: a signed header could be dropped without breaking the signature. A value with a line break once decoded is now `ErrMalformed`. | [`5489f85`][5489f85] |
| Decrypting a message's parts cost time in parts × document size | Each `Decrypt`, `Unwrap` and `Derive` call costs time in the document's size: a same-document `CipherReference` source is decoded again, `DecryptAndReplace` and `DecryptHeader` re-emit the whole document, and `FindEncryptedKey` walks it. Nothing bounded the parts, so a 4 MB message with 16,000 parts took 12.7 s before anything was authenticated. Every such function now refuses a document holding more than `DecryptOptions.MaxEncryptedParts` (new; zero means the new `xenc.DefaultMaxEncryptedParts`, 64) `EncryptedData`, `EncryptedKey` and `DerivedKey` elements, with `ErrLimitExceeded`, before any key lookup or cryptography. | [`5489f85`][5489f85] |
| One `FindEncryptedKey` call walked the document once per `ds:RetrievalMethod` | Any number of `RetrievalMethod`s naming one key are allowed, and each was looked up: a 2.7 MB message took 10.4 s. Each distinct URI is now looked up once, and every child is still checked. | [`5489f85`][5489f85] |
| `StrictX509Data` matched an unbounded number of `X509Data` descriptors before `TrustKey` | Each descriptor re-hashed or re-parsed the carried certificates: a 1.2 MB message took 950 ms before `TrustKey` could refuse it. More than 64 descriptors in one `ds:KeyInfo` are now `ErrUnsupportedKeyInfo`, before any is matched; a pinned key ignores the refusal as before. | [`5489f85`][5489f85] |
| An XPath transform's cost grew with root declarations × elements | Every element has a namespace node per binding in scope, so k declarations over m elements gave k × m evaluations from k + m parsed nodes: a 145 KB message took 8.9 s to verify. The XPath and Filter 2.0 transforms now decide at most 4096 namespace nodes plus 256 per other input node, and refuse more with `ErrLimitExceeded`. | [`5489f85`][5489f85] |

### Changed — documentation

| Change | Problem → solution | Commit |
|---|---|---|
| Allowing CBC exposes keys that protect AES-GCM data | A transported session key carries no data algorithm, and a ConcatKDF or PBKDF2 derivation takes only the message's parameters and the key size, so an attacker's CBC `EncryptedData` can use a key made for AES-GCM or key wrap. XML Encryption 1.1 defines no binding that would refuse it. docs/security.md now says to give CBC peers their own key pair, password or master key and `DecryptOptions`. | [`5489f85`][5489f85] |

### Changed — memory

| Change | Problem → solution | Commit |
|---|---|---|
| The XSLT transform compiled a copy of the stylesheet | go-xml v2.3.0 streamed only a stylesheet compiled from a document node, so v2.1.0 compiled one holding a copy of the stylesheet, with the namespaces in scope at `ds:Transform` declared. go-xml v2.3.1 streams one compiled from its element, and the stylesheet is compiled where it stands, with no copy. Output and the 10 MiB peaks are unchanged (streamed 1.85×, tree 6.0×, with `Sign` and `Verify`). | [`dc5b096`][dc5b096] |
| `go-xml` v2.3.0 → v2.3.1 | Streaming of a stylesheet compiled from its element, nested in another document. Nothing else changed. | [`dc5b096`][dc5b096] |

## v2.1.0 — 2026-11-12

go-xml v2.3.0, whose streaming the XSLT transform now uses, and XPath
filters evaluated by XPath 1.0 rules. No exported API changes. Digests,
signatures and ciphertext are byte-identical to v2.0.2 but for an XPath
filter whose result depends on the number rules, listed under
*Changed — behaviour*.

### Fixed — security

| Change | Problem → solution | Commit |
|---|---|---|
| `xenc.ReferencedData` still checked for duplicate references quadratically | v2.0.2's single walk left a scan of the result for each reference: 80,000 references took 25 s under the race detector, and CI's 20,000-reference test failed its 2 s limit on every OS. Duplicates are found with a set; 80,000 references: 1 s under the race detector. | [`8baed7c`][8baed7c] |

### Changed — behaviour

| Change | Problem → solution | Commit |
|---|---|---|
| XML-DSig XPath expressions were evaluated in XPath 2.0's 1.0 compatibility mode | XML-DSig specifies XPath 1.0, and compatibility mode still used 2.0's number model: `number('1e3')` was 1000 and `"10" < "9"` compared strings. Expressions, in the XPath and XPath Filter 2.0 transforms and in an xenc `CipherReference`, are compiled with go-xml's new XPath 1.0 mode, as go-xml's own c14n XPath transforms now are: `number('1e3')` is NaN, a comparison converts strings to numbers, `1 < 2 < 3` compiles, and an exponent literal is `ErrMalformed`. An allowed expression that depends on these selects what xmlsec1 and Santuario select. | [`be0430c`][be0430c] |

### Changed — memory

| Change | Problem → solution | Commit |
|---|---|---|
| The XSLT transform built its input and its result as trees | It runs through go-xml's `TransformReader`, parsing with `xmlsec.Parse`'s options, and writes its output as it is produced with `TransformOptions.Output`. A stylesheet whose initial mode is streamable (XSLT 3.0 `<xsl:mode streamable="yes"/>`) builds no tree of its input. An identity transform of 10 MiB alone: XSLT 1.0 on the tree 8.97× → 5.68×, XSLT 3.0 streamed 8.15× → 0.20×; with `Sign` and `Verify` around it, 9.3× → 6.1× and 8.3× → 5.3×. The stylesheet is compiled from a document holding a copy of it, with the namespaces in scope at `ds:Transform` declared, because go-xml v2.3.0 streams only a stylesheet compiled from a document node. Output is unchanged. | [`be0430c`][be0430c] |
| `go-xml` v2.2.0 → v2.3.0 | XSLT streaming, the XPath 1.0 mode, and its hardening release. Canonical output is unchanged: the c14n conformance figures are the same, and the golden hashes and the interop suite pass. `ParseOptions.MaxNodes` now also counts text that is not all white space, comments and PIs, so a document near the 10,000,000-node limit may now be refused. | [`be0430c`][be0430c] |
| `Parse` memory figures | Re-measured on go-xml v2.3.0: still about 13 times the input at worst (attributes 12.4×, namespace declarations 10.4×); [docs/security.md](docs/security.md#resource-limits). | [`be0430c`][be0430c] |

## v2.0.2 — 2026-11-02

Fixes for resource exhaustion before authentication, two correctness fixes,
and the go-xmlsec findings of two memory audits. No exported API changes.
Digests, signatures and ciphertext are byte-identical to v2.0.1, which tests
pin with golden hashes taken from it; the one changed output is the
`DecryptHeader` namespace fix under *Fixed*. The new refusals are listed
under *Fixed — security*, each far above anything deployed.

### Fixed — security

| Change | Problem → solution | Commit |
|---|---|---|
| A PkiPath or PKCS7 `BinarySecurityToken` of many tiny elements exhausted memory before authentication | Resolving the signer's key decoded a PkiPath into a slice of every element, and read every SignedData field, before the signature was checked: a 60 MiB message of 2-byte NULLs allocated 4.2 GB (PkiPath) or 3.3 GB (PKCS7), about 77× and 59× the token. The PkiPath is walked one element at a time, keeping only the last, and refused past 16 certificates with `ErrUnsupportedKeyInfo`, as PKCS7 already was; a seventh SignedData field is `ErrMalformed`. Peak heap is now 0.76× the token (the base64 decode). `AddBinarySecurityToken` refuses a PkiPath chain of more than 15 beside the certificate. | [`38e44ca`][38e44ca] |
| `xenc.ReferencedData` walked the document once per reference | A received `ReferenceList` of n references cost n walks of the message before any decryption: 20,000 took 6 s, and the parse limits allow far more. One walk now finds every requested ID; results and errors, in order, are unchanged. 20,000 references: 0.08 s. | [`be398ff`][be398ff] |
| An RSA key had no maximum size | A 1 MiB `ds:Modulus` in `ds:KeyValue` cost 110 s of CPU and 37 GB in RSA verification before the signature was rejected, and nothing in `crypto/rsa` or `crypto/x509` caps it. RSA keys over 16,384 bits (OpenSSL's limit) are refused with `ErrUnsupportedKeyInfo`, raw keys before they are decoded, in `ds:KeyValue`, `dsig11:DEREncodedKeyValue`, every `ds:X509Certificate` and every `BinarySecurityToken` certificate. A pinned key still tolerates such a certificate in `ds:KeyInfo`. | [`be398ff`][be398ff] |
| An `InclusiveNamespaces` PrefixList was deduplicated quadratically | 1 MiB of distinct prefixes took 12 s in go-xml's `c14n.ParsePrefixList`. More than 1,024 prefixes is `ErrMalformed`, before parsing. | [`be398ff`][be398ff] |
| `X509SerialNumber` was parsed quadratically | `big.Int.SetString` on 1 MiB of digits took 0.9 s and 2.4 GB. In `ds:X509IssuerSerial` more than 128 digits is `ErrMalformed`; `wss.MatchSecurityTokenReference` reports no match, before parsing, for more digits than the certificate's serial. At most 16 `ds:X509CRL` are read, and none with a pinned key. | [`be398ff`][be398ff] |

### Fixed

| Change | Problem → solution | Commit |
|---|---|---|
| `Sign`, and `Verify` with `RequireNFC`, refused a base64 transform over binary content | The Unicode normalization check (XML-DSig 8.1.3) ran over the octets the transform decoded, so random bytes were `ErrNotNFC`. Decoded octets are no longer checked; canonical XML and XSLT output still are. | [`be398ff`][be398ff] |
| `DecryptHeader` put a decrypted block in the SOAP Header's default namespace | An `EncryptedHeader` carrying `xmlns=""` under a Header with a default namespace gave its block's unprefixed elements the Header's namespace, in the parse and in the output (XML Encryption 1.1 section 4.5.4). The undeclaration is kept. | [`be398ff`][be398ff] |

### Changed — memory

| Change | Problem → solution | Commit |
|---|---|---|
| An `xmlsec.Document` kept every earlier tree | Each change kept a map from every node to its copy, whose keys pinned every old tree: the send flow (`AssignID`, `NewHeader`, timestamp, token, `dsig.Sign`, `Prepend`) peaked at 55× and retained 53× a 1 MiB message. Each change now keeps runs of positions (`Node.Index`) and holds earlier trees only by weak pointer; `Node` answers as before. Peak 11×, retained 5.3×, allocation −57%. A `wss.Header` holds its element in the latest tree. | [`7bfc182`][7bfc182], [`be398ff`][be398ff] |
| The BSP R5205 token-order check and every new ID built a map over the document | Outside a header, the order check numbered every element (10× the document at 1 MiB); it compares `Node.Index`. A new or supplied ID was checked against a set of every ID value (2.3× on an ID-dense document); each candidate is looked for by walking. Results and errors are unchanged. | [`7bfc182`][7bfc182] |
| The NFC check of `Sign`, and of `Verify` with `RequireNFC`, buffered the whole canonical form | It is checked as written, keeping only the text after the last normalization boundary: a detached `Sign` at 10 MiB peaks at 0.017× the reference (from 2.65×), `Verify` with `RequireNFC` at 0.016×. Tested against whole-buffer `IsNormal` over random write splits. | [`7bfc182`][7bfc182] |
| The XPath transform made an evaluation context for every node, and both XPath transforms kept a map entry per node of their output | One context per transform, refocused per node; the output node set is a bitset by `Node.Index`. XPath 1.0 allocation 133× → 54× the document, XPath Filter 2.0 subtract peak 16.8× → 0.88×. The go-xml node budget (`MaxNodes`) is now charged across the transform rather than per node: stricter, and unreachable by an XPath 1.0 filter, which constructs no nodes. | [`7bfc182`][7bfc182] |
| Encryption and decryption copied their buffers | `EncryptElement`, `EncryptContent` and `EncryptHeader` seal AES-GCM in place and write base64 straight into the text (allocation 6.0× → 3.8× at 10 MiB); decryption opens in the buffer it decoded, never in bytes the caller supplied (`DecryptData` 2× → 1×); `DecryptAndReplace` and `DecryptHeader` rebuild the document without a node map (peak 8.7× → 7.1×); `EncryptAttachment` Complete seals one buffer (2× → 1×); a wrapped `CipherValue` is decoded in chunks (1.73 → 0.73 bytes per text byte, twice as fast). | [`7bfc182`][7bfc182] |
| `DecryptAndReplace` and `DecryptHeader` copied the decrypted tree into the document | The document is rebuilt and canonicalized with a random comment in the `EncryptedData`'s place, and the plaintext, parsed straight from the decrypted bytes under a wrapper declaring the namespaces in scope there, is canonicalized into that spot. Peak 7.1× → 4.75×, allocation 8.65× → 4.78× at 10 MiB. A document element, a comment already in the document, or content near the canonicalization depth limit takes the old path. Byte-identical: `TestSpliceMatchesEmit` holds 519 decryptions to the v2.0.1 path. | [`be398ff`][be398ff] |
| `EncryptElement`, `EncryptContent` and `EncryptHeader` held the ciphertext's base64 as text twice | The `CipherValue` holds a random marker while the document is canonicalized, and the base64 is encoded straight into the output allocated once: 3.76× → 2.33× at 10 MiB, golden hashes unchanged. A document that already holds the marker is refused, by chance only. | [`be398ff`][be398ff] |
| An external base64 `CipherReference`, and one an XPath selects, joined their text before decoding | The text is decoded in place, a chunk at a time, from the resolved bytes or the selected text nodes: base64 3.94× → 0.74×; the XPath transform also uses one evaluation context, refocused per text node: 23.1× → 10.8× allocated at 10 MiB. White space other than XML's takes the old decoding, so results and errors are unchanged. | [`be398ff`][be398ff] |
| Derived key material stayed in memory | Agreed, DH and password KEKs, shared secrets, derived data keys, failed unwrap outputs, CBC plaintext with bad padding and parsed plaintext are cleared after use; caller keys never are. | [`be398ff`][be398ff] |
| `go-xml` v2.0.3 → v2.2.0 | Three memory releases that addressed what go-xmlsec reported. v2.1.0: pooled c14n buffers (a 50-reference `Verify` 8.3 MB → 0.15 MB), sized `c14n.Bytes` (3.6× → 1.2× the output), and `Node.Index` and `Tree.NodeAt`, which the `Document` change uses. v2.1.1: a large text value parsed at 1.1× (from up to 2.2×), `ParsePrefixList` linear (9.6 s → 13 ms on 1 MiB), attribute- and namespace-heavy tags about half the memory, and positional predicates that stop at their match (XPath Filter 2.0 intersect peak 1.08× → 0.03×). v2.2.0: namespace nodes freed when unused (XPath transform peak 8.1× → 0.66×) and smaller trees (rebuilds −4%). Canonical output is unchanged. | [`7bfc182`][7bfc182], [`97b8da3`][97b8da3] |
| `Parse` memory figures | Re-measured on go-xml v2.2.0: about 13 times the input at worst, from about 40; [docs/security.md](docs/security.md) has the table. | [`7bfc182`][7bfc182], [`97b8da3`][97b8da3] |
| The base64, XSLT and STR transforms buffered their output | Base64 decodes a chunk at a time and, as the last transform, streams into the digest (peak 3.75× → 0.01× at 10 MiB); XSLT and the STR Dereference Transform stream when last (XSLT allocation −5×); octets are released once re-parsed; the NFC buffer is pooled. XPath Filter 2.0 records only whether anything was cut (intersect peak 2.65× → 1.48×), and the XPath 1.0 transform reuses one context (allocation 54× → 41×). | [`be398ff`][be398ff] |
| wss walked or collected every child of wide elements, and quoted whole attacker values in errors | Lookups stop at the elements they need (about 10× → 0 on a wide header or Security element); a value quoted in an error is cut at 64 bytes (an error was 3× the input); issuer names fold in one pass (10× → 2×); `CheckUniqueIDs` sorts instead of mapping (4× → 1.2×). | [`be398ff`][be398ff] |
| SwA transforms not last in a reference grew their buffer by doubling | A regression from v2.0.1's streaming: XML 7.4× → 5.5×, text 2.8× → 1.1×. `Selected` builds its replacer once (62 → 17 allocations), and Content-Type is parsed once. | [`be398ff`][be398ff] |

## v2.0.1 — 2026-10-31

No API change.

### Changed

| Change | Why | Commit |
|---|---|---|
| The SwA Attachment-Content and Attachment-Complete signature transforms stream the canonical form into the digest when they are a reference's last transform | An XML attachment's canonical form is no longer held in memory: peak heap falls from about 7× to 4.5× the attachment for invoice-shaped XML, and from 2× to near 0 for text. Digests are byte-identical, checked against the v2.0.0 path by a corpus test and `FuzzWriteContent`. | [`7483b9f`][7483b9f] |
| `go-xml` v2.0.1 → v2.0.3 | Two cost fixes from an external audit, no API change: parsing was quadratic in the namespace declarations in scope (100k declarations and 300k attributes took 33 s, now 0.35 s), and `fn:normalize-space` allocated a list of every token. `c14n` is unchanged, so canonical output and digests are the same. || [`040dd04`][040dd04] |

## v2.0.0 — 2026-10-19

New module path `github.com/knroy/go-xmlsec/v2`, on go-xml v2.
go-xml v2's parsed trees cannot be changed, so the calls that add to a
document take an `xmlsec.Document` and build a new tree for each change.
[docs/migrating-to-v2.md](docs/migrating-to-v2.md) has before/after code for
every changed call. v1 continues at `github.com/knroy/go-xmlsec`, with fixes
released from the `v1` branch.

### Changed — breaking

| Change | Why | Commit |
|---|---|---|
| Module path `github.com/knroy/go-xmlsec/v2` | A breaking change needs a new module path. Import `github.com/knroy/go-xmlsec/v2/<package>`. | [`fcf935d`][fcf935d] |
| `go-xml` v1.6.0 → v2.0.1 (`github.com/knroy/go-xml/v2`); `golang.org/x/text` v0.36.0 → v0.41.0 | Security-relevant, per RELEASE.md. go-xml's changelog lists no change to canonical output between the two, only faster canonicalization; its parser fixes are in DTD processing, which `xmlsec.Parse` refuses. `x/text` v0.36.0 loops forever on some invalid input (GO-2026-5970). Nodes are read through methods (`n.Kind()`, `n.Children()`), and a parsed tree is frozen. | [`fcf935d`][fcf935d] |
| `dsig.Sign` takes an `*xmlsec.Document` | With `SignOptions.Parent` the signature is placed in a new tree, which becomes `doc.Root()` on success; the returned element is the placed signature. Without `Parent`, `doc` is only read; nil is still an enveloping signature. `SignEnveloped`, `Verify` and `BuildManifest` still take an `*xdm.Node`. | [`fcf935d`][fcf935d] |
| `wss.NewHeader` takes an `*xmlsec.Document` | `NewHeader` and every `Header` method change the document; `Header.Element` is the `wsse:Security` element in the latest tree. `Prepend` and `Append` place a copy of their element: `doc.Node(el)` finds it. | [`fcf935d`][fcf935d] |
| `wss.AssignID` and `AssignIDWith` take an `*xmlsec.Document` | The element may come from any earlier tree of the document; one not in it, such as an `xenc:EncryptedKey` not yet placed, is refused with `ErrMalformed`. | [`fcf935d`][fcf935d] |
| `xenc.EncryptedKey.SetKeyInfo`, `AddDataReference` and `AddKeyReference` replace `ek.Element` with a new element | The old one cannot be changed. Call them before placing `ek.Element`: a copy already in the header is not updated. | [`fcf935d`][fcf935d] |

### Added

| Change | Commit |
|---|---|
| `xmlsec.Document`, `xmlsec.NewDocument`, `Document.Root` and `Document.Node`: a document that `dsig.Sign`, `wss.NewHeader` and `wss.AssignID` add to, its latest tree, and an earlier tree's node in it | [`fcf935d`][fcf935d] |
| `wss.WithID`: a copy of a detached element carrying an ID, set as `AssignID` sets it, for an element that needs one before it is placed, such as a `SignOptions.KeyInfoElement` named by the STR Dereference Transform | [`fcf935d`][fcf935d] |
| [docs/migrating-to-v2.md](docs/migrating-to-v2.md) | [`fcf935d`][fcf935d] |

## v1.3.0 — 2026-10-08

Fixes from an independent audit, run without reference to this project's own
claims: five auditors (XML Signature, XML Encryption, WS-Security, security,
sanity), every finding reproduced. The security audit found nothing
exploitable; these are specification divergences, API edges and documentation
that overstated the code.

### Fixed

| Change | Why | Commit |
|---|---|---|
| A detached `Sign` refuses a placement-dependent transform (inclusive C14N, a PrefixList, XPath, XSLT, the STR transform of an embedded token) on a reference into the signature itself | It was digested before the signature was placed, so the signature never verified once placed (XML Signature §4.4.3.3). | [`ddea0d6`][ddea0d6] |
| `EncryptionProperties` with `MasterKey`, `Password` or `DirectKeyAgreement` keeps `ds:KeyInfo` before `CipherData` | The output was schema-invalid, and this library could not decrypt it (XML Encryption §3.1). | [`1146d94`][1146d94] |
| The STR Dereference Transform dereferences a SAML key identifier to the assertion in the document, and refuses other non-X.509 key identifiers | It built and digested an X.509 token for any key identifier (SOAP Message Security §8.3). | [`7e0f8aa`][7e0f8aa] |
| Attachment-Complete decryption reports every failure after decryption as `ErrDecryptionFailed` | Detailed header errors on CBC data were a format oracle (XML Encryption §6.1.1). | [`1146d94`][1146d94] |
| No method panics on a nil or zero value: `Coverage`, a `wss.Header` not from `NewHeader`, an `EncryptedKey` with no element | `docs/security.md` promised errors, never panics. | [`ddea0d6`][ddea0d6], [`7e0f8aa`][7e0f8aa], [`1146d94`][1146d94] |
| `VerifyManifest` refuses the enveloped-signature transform in a Manifest outside any `ds:Signature` | It removed the Manifest itself; the specification's output is empty (§6.6.4). | [`ddea0d6`][ddea0d6] |
| The base64 transform ignores characters outside the alphabet; a pinned key ignores an unparsable `ds:X509Certificate`; `RetrievalMethod` without `Type` infers it; certificates for one public key count as one leaf | XML Signature §6.6.2 (RFC 2045), §3.2.2, §4.5.3, §4.5.4. | [`ddea0d6`][ddea0d6] |
| A Content-Only attachment without a Content-Type is encrypted with `MimeType` `text/plain; charset=us-ascii`; the `xenc11#DerivedKey` `RetrievalMethod` Type is accepted; `DigestSHA384XMLEnc` is accepted on encryption; ConcatKDF parameters are concatenated bit by bit | SwA §5.5.2, XML Encryption §3.5.2, §5.8.3, §5.4.1. | [`1146d94`][1146d94] |
| Strict token-reference resolution applies R3066 only inside a `wsse:Security`; `CheckSecurityTokenReference` enforces R3069 and R6604 and reports unknown profiles as `ErrUnsupportedKeyInfo`; a `BinarySecurityToken` without `EncodingType` is Base64Binary when lenient; `ParseTimestamp` accepts more than three fractional digits and a zero offset | BSP and SOAP Message Security §6.3, §10. | [`7e0f8aa`][7e0f8aa] |
| A refused DOCTYPE is `ErrMalformed` | It wrapped no sentinel and suggested a go-xml option callers cannot reach. | [`126f886`][126f886] |

### Changed

| Change | Why | Commit |
|---|---|---|
| `GenerateEncryptedKey` and the Encrypt functions refuse `EncryptOptions` fields that do not apply to the chosen key transport, wrap or derivation, and `PBKDF2Iterations` without `Password` or out of range | They were silently ignored. | [`1146d94`][1146d94] |
| An `xenc:CipherReference` without a `URI` attribute is refused; an attachment's must carry the Attachment-Ciphertext-Transform | One read as the whole document; SwA §5.5.1 requires the transform. | [`1146d94`][1146d94] |
| The STR transform accepts any allow-listed canonicalization (Exclusive C14N only under `StrictBSP`), and `Sign` states `#default` in the PrefixList it emits | §8.3 takes any canonicalization; the emitted XML now says what is digested. | [`7e0f8aa`][7e0f8aa] |

### Added

| Change | Commit |
|---|---|
| `xenc.DecryptOptions.ImpliedKeyDerivationMethod`, for an `xenc11:DerivedKey` without a `KeyDerivationMethod` (§3.5.2), allow-listed like the other `Implied*` options | [`1146d94`][1146d94] |

### Documented and tested

| Change | Commit |
|---|---|
| The deliberate exceptions, stated in `docs/security.md`: DOCTYPE refused when octets are re-parsed, XPath in a 2.0 engine's 1.0 mode, combined `KeyInfo` forms, raw RSA keys under 2048 bits, DH groups under 2048 bits, several keys in one `KeyInfo`, `kw-tripledes` parity unchecked (xmlsec1 wraps without it), and the three SwA header canonicalization departures WSS4J requires. The default allow-lists named. The `docs/usage.md` examples that did not compile fixed. | [`f320ad2`][f320ad2], [`1146d94`][1146d94], [`7e0f8aa`][7e0f8aa], [`391978c`][391978c] |
| Security tests assert the refusal they claim; the version test requires the newest changelog section; CI lints the `interop` code and `tests/w3c`; `docs/testing.md` no longer claims no clock, no network and no `#nosec` | [`feb2a92`][feb2a92], [`94c506f`][94c506f] |

## v1.2.2 — 2026-10-07

### Changed

| Change | Why | Commit |
|---|---|---|
| `go-xml` v1.4.0 → v1.6.0 | Security-relevant, per RELEASE.md. Canonicalization: Exclusive C14N no longer renders a namespace node an XPath filter removed (Exc-C14N §1.1), which only the opt-in XPath transforms reach; no other canonical output changed, and the interop suite, the W3C vectors and the real-message corpus are unchanged. Parsing: a new tokeniser replaces the `encoding/xml` fork, refusing 20 not-well-formed documents it accepted and accepting 16 well-formed ones it refused, so `xmlsec.Parse` is stricter on malformed input and more complete on DTD edge cases (DOCTYPE stays refused). The Go floor is unchanged: `go-xml` still needs 1.25. | [`57683c8`][57683c8] |

## v1.2.1 — 2026-09-28

### Tested

| Change | Commit |
|---|---|
| Canonical XML 1.1 compared against xmlsec1 and Santuario: whole documents both ways, and byte-identical signatures over a subset whose ancestors carry `xml:base`, `xml:lang`, `xml:space` and `xml:id`. Found a Santuario 4.0.4 divergence: with two omitted ancestors carrying `xml:base` it joins only one; this library agrees with xmlsec1 and C14N 1.1 §2.4, and a test keeps the divergence visible. | [`663bfe5`][663bfe5] |

## v1.2.0 — 2026-09-28

### Added

| Change | What it does | Commit |
|---|---|---|
| Explicit IDs for reproducible output | `wss.AssignIDWith`, `Header.AddBinarySecurityTokenWithID`, `AddTimestampWithID` and `AddSignatureConfirmationWithID` take the caller's ID instead of minting one: with every ID and the clock supplied, a signed AS4 message is byte-identical from run to run, for golden files and differentials against other implementations. No package state; the minting functions share the same path. | [`cf8c78b`][cf8c78b] |
| `Coverage.CoversNodes` | Checks covered elements by node identity. `Covers`, an ID check, is satisfied by a signature-wrapped document when the application then finds the element by position; its documentation now says so, and says when `CoversAttachments` is safe. | [`cf8c78b`][cf8c78b] |

### Documented

| Change | Commit |
|---|---|
| The Go 1.26 floor: `go-xml` needs 1.25, and `rsa.EncryptOAEPWithOptions`, for an MGF digest unlike the OAEP digest, needs 1.26 (RELEASE.md). `KeyTransportRSAOAEP` is the one to use; `KeyTransportRSAOAEPMGF1P` is the decryption-only 1.0 algorithm. | [`cf8c78b`][cf8c78b], [`cb813c1`][cb813c1] |
| Canonicalization: what `go-xml/c14n` measures (the W3C C14N 1.1 interop cases, the Recommendations' examples, differentials against `xmllint` and `xmlsec1`), what this module checks independently, and that Canonical XML 1.1 is compared against no other implementation here (docs/testing.md). | [`afb42a1`][afb42a1] |

## v1.1.0 — 2026-09-26

Every requirement of the implemented specifications that v1.0.0 left out,
found by a clause-by-clause audit of XML Signature 1.1, XML Encryption 1.1,
SOAP Message Security 1.1.1, the X.509 Token and SwA profiles and BSP 1.1.
Every new feature is an opt-in; the few changes to what a v1.0.0 caller sees
are listed under Changed.

### Added

| Change | What it does | Commit |
|---|---|---|
| XPath, XPath Filter 2.0 and XSLT transforms as opt-ins | `dsig.Sign` produces them from `TransformSpec.XPath`, `XPathNamespaces`, `XPathFilters` (`dsig.XPathFilter`) and `Stylesheet`. `dsig.Verify` evaluates them only for programs in `VerifyOptions.AllowedXPathExpressions` (`dsig.XPathExpression`) or `AllowedXSLTStylesheets` (exact text, prefix bindings checked, compiled from the allow-list; stylesheets matched under Exclusive C14N), refusing anything else with `ErrTransformRefused` before any cryptographic work. `here()` supported; XSLT sandboxed with no resolvers and bounded output; `Coverage` drops any target a filter partly removed, and XSLT output covers nothing. Byte-identical transform output with Santuario; `here()` verified by xmlsec1. | [`13a61dc`][13a61dc] |
| External URI dereferencing through a caller resolver | `xmlsec.URIResolver`, passed as `dsig.SignOptions.ResolveURI`, `dsig.VerifyOptions.ResolveURI` or `xenc.DecryptOptions.ResolveURI`, supplies the octets of an absolute non-`cid:` URI in a `ds:Reference` or `xenc:CipherReference` (XML Signature §4.4.3.1); the library still never fetches. On verification it is called only after the allow-lists, `TrustKey` and the signature value pass; external references are reported in `Coverage.ExternalURIs`; errors wrap the new `xmlsec.ErrDereference`. Relative URIs resolve only against a caller's `BaseURI` (below). | [`57349cb`][57349cb] |
| PKCS7 binary security tokens | `xmlsec.BSTValueTypePKCS7`: `AddBinarySecurityToken` emits a DER certs-only PKCS#7 SignedData; `ParseBinarySecurityToken`, token references and `dsig.Verify` read one strictly (SignedData v1, data content, X.509 only, at most 16 certificates; CRLs and signer infos ignored) and return the one certificate that issued none of the others, or `ErrUnsupportedKeyInfo`. Byte-identical to OpenSSL `crl2pkcs7` and the JDK's PKCS#7 encoder. | [`bec715d`][bec715d] |
| Finite-field Diffie-Hellman and PBKDF2 (XML Encryption 1.1 §5.6.2, §5.4.2) | `xenc.DecryptAgreedKeyDH`, `DHPublicKey`, `DHPrivateKey`, `GenerateDHKey` and `EncryptOptions.RecipientDH`/`RecipientKeyName` add `dh-es` and the legacy `dh` (`xmlsec.KeyAgreementDHES`, `KeyAgreementDH`) in groups of `xenc.MinDHBits` to `MaxDHBits` (2048–8192 bits) with subgroup validation; `UnwrapEncryptedKeyPassword` and `EncryptOptions.Password`/`PBKDF2Iterations` (default `xenc.DefaultPBKDF2Iterations`) add PBKDF2 (`xmlsec.KeyDerivationPBKDF2`), also usable as a key agreement's KDF, with received iteration counts bounded to `MinPBKDF2Iterations`–`MaxPBKDF2Iterations` (1000–10,000,000) before any work. New `DecryptOptions.AllowedKeyDerivationAlgorithms` (default ConcatKDF) and `AllowedPRFAlgorithms`; none of the new algorithms is in a default set. Checked against xmlsec1 in both directions. | [`6736ffd`][6736ffd] |
| XML Signature structures and HMAC generation | `SignOptions.Objects` (`dsig.Object`; enveloping signatures, with a nil document) and `Properties` (`dsig.SignatureProperty`, in `ds:SignatureProperties`); `SignedInfoID`, `SignatureValueID`, `KeyInfoID`, with `KeyInfo` and Objects built before digesting so a reference can sign them; a signature's own Object, KeyInfo, Manifest and SignatureProperty Ids resolve without `IDAttrDSig`; `BuildManifest` and `VerifyManifest` (`xmlsec.TypeManifest`, `SignOptions.ManifestID`), which refuses a Manifest the signature does not cover; `CanonicalizationPrefixes`; `Reference.OmitURI` with `OmittedURIData`; `BaseURI` on Sign and Verify for relative URIs, never `xml:base`; HMAC-SHA224/256/384/512 produced with `HMACKey` and `HMACOutputLength`; `VerifyOptions.RequireNFC`. Interop with Santuario and xmlsec1. | [`1eb3aaa`][1eb3aaa] |
| XML Signature `KeyInfo` forms and algorithms | `ds:KeyName` (`Coverage.KeyName`, `ResolveKeyName` when alone); `X509Data` chains of up to 16 with one leaf (`Coverage.Intermediates`), `X509CRL` (`Coverage.CRLs`), `X509IssuerSerial`, `X509SKI`, `X509SubjectName` and `dsig11:X509Digest`, checked against the carried certificates under `StrictX509Data` and resolved through `ResolveX509` (`dsig.X509Identifier`) when no certificate is carried; same-document `RetrievalMethod`, one hop; `rawX509Certificate` and external `KeyInfoReference` through `ResolveKeyInfoURI`; DER-encoded DSA keys. Sign: `KeyName`, `Chain`, `X509Descriptors` (`dsig.X509Descriptor`), `KeyInfoReferenceURI`, and the forms `KeyInfoKeyName`, `KeyInfoX509Descriptors` and `KeyInfoReference`. Algorithms: `xmlsec.DigestSHA224`, `SigRSASHA224`, `SigECDSASHA224` and `SigHMACSHA224`, outside the default sets; `SigDSASHA256` and `SigECDSASHA1`, verification only. | [`51d76cc`][51d76cc] |
| XML Encryption data side | `EncryptOctets` for arbitrary octets with `Type`, `MimeType` and `Encoding`, inline or by `CipherReference` (`EncryptOptions.CipherReferenceURI`); `DecryptAndReplace`, including an `EncryptedData` that is the document element; `EncryptionProperties`; `DecryptOptions.BaseURI` for relative `CipherReference` URIs; `DecryptOptions.AllowedXPathExpressions` for XPath then base64 on a `CipherReference`, checked before `ResolveURI` and any decryption. `SetKeyInfo` and `AddDataReference` place children in schema order. | [`11aa01d`][11aa01d] |
| XML Encryption `KeyInfo` forms | an `EncryptedKey` with a `CipherReference`; `FindEncryptedKey` on an `EncryptedKey`, `KeyReference` and `EncryptedKey.AddKeyReference`; `TypeDerivedKey`, `FindDerivedKey`, `DeriveKey` and `EncryptOptions.MasterKey`, `MasterKeyName` and `DerivedKeyName`; `DecryptAgreedDataKey`, `DecryptAgreedDataKeyDH` and `EncryptOptions.DirectKeyAgreement`; `KA-Nonce` beside ECDH-ES and `dh-es` accepted and ignored; `DecryptOptions.ImpliedDataAlgorithm`, `ImpliedKeyWrapAlgorithm` and `ImpliedKeyTransportAlgorithm` for an absent `EncryptionMethod`; `xmlsec.MGF1SHA224`, opt-in on receipt. | [`bf72db6`][bf72db6] |
| WS-Security symmetric binding and decryption | `EncryptOptions.DataKeyInfo`, `wss.NewReferenceList`, `xenc.ReferencedData`, `xenc.DecryptHeader`; `FindEncryptedKey` follows a `wsse:SecurityTokenReference` to an `EncryptedKey`; `DecryptOptions.StrictBSP` (R3209, R5622, R5623, R5602, R5424, R5426, R3228, R5629, before any key is used); `xmlsec.ErrDecryptionFailed`, wrapped by every decryption and unwrap failure; `EncryptHeader` generates an Id when `DataID` is empty; an `EncryptedKey` reference carries `wsse11:TokenType`. WSS4J interop both ways. | [`996144a`][996144a] |
| WS-Security conformance | STR Dereference Transform (`xmlsec.TransformSTR`, `ResolveSecurityToken`, `Coverage.SignedTokens`); key identifier and issuer-serial `KeyInfo` (`SignOptions.KeyInfoElement`); `wsse:Embedded` and `wss.ReferencedToken`; `EncryptedKey` references by Id and `EncryptedKeySHA1` (`NewEncryptedKeyReference`, `NewEncryptedKeySHA1Reference`, `MatchEncryptedKeySHA1`); `SignatureConfirmation` (`AddSignatureConfirmation`, `SignatureValues`, `CheckSignatureConfirmations`); `FindHeader`, `FindTimestamp`, `CheckUniqueIDs`, `CheckSecurityTokenReference`; `wss.FaultCode` with `xmlsec.ErrInvalidSecurityToken` and `ErrSecurityTokenUnavailable`; `VerifyOptions.StrictBSP`. Byte-identical STR transform output with WSS4J. | [`caaf44e`][caaf44e] |
| `VerifyOptions.StrictX509Data` | Refuses an `X509IssuerSerial`, `X509SKI`, `X509SubjectName` or `dsig11:X509Digest` beside the carried certificates that describes none of them (XML Signature §4.5.4). Off by default, as in v1.0.0: a real PEPPOL SMP response carries an `X509SubjectName` left stale by a certificate renewal, which Santuario also accepts. | [`7a6a367`][7a6a367] |

### Changed

| Change | Why | Commit |
|---|---|---|
| `Sign` refuses content not in Unicode Normalization Form C with `ErrNotNFC`, whose message now reads "not in Unicode Normalization Form C" | XML Signature §8.1.3: every document a signature application generates MUST be in NFC. | [`1eb3aaa`][1eb3aaa] |
| `Sign` refuses the base64 transform after an SwA attachment transform | SwA profile §5.4.4 and BSP R6101: attachment references MUST NOT carry base64 or transfer-encoding transforms. | [`caaf44e`][caaf44e] |
| `wss.AssignID` returns an element's existing `xml:id` instead of adding a `wsu:Id` | SOAP Message Security §4: an element MUST NOT carry both. | [`caaf44e`][caaf44e] |
| An enveloped-signature transform over a node set parsed from octets is `ErrMalformed` | XML Signature §6.6.4: it applies only to a node set from the signature's own document; it used to do nothing. | [`1eb3aaa`][1eb3aaa] |
| A few refusals changed kind: an XPath transform with an expression is `ErrTransformRefused` (was `ErrMalformed`); a PBKDF2 key derivation under the default lists is `ErrAlgorithmNotAllowed` (was `ErrUnsupportedAlgorithm`) | Each now names what the caller can change: the allow-list. | [`13a61dc`][13a61dc], [`6736ffd`][6736ffd] |

## v1.0.0 — 2026-09-26

First release.

### Added

| Change | What it does | Commit |
|---|---|---|
| Root package `xmlsec` | Algorithm and namespace URI constants, sentinel errors, `Attachment` and `AttachmentSet` with RFC 2392 percent-decoding, `KeyProvider`, and `Parse` — the one pinned set of parse options verification runs against: DOCTYPE refused, no entity resolver, depth 1000, 64 MB, 10M nodes, and `c14n.MaxDepth` set to 500 explicitly. | [`9756c04`][9756c04] |
| Package `wss` | `wsse:Security` header construction for SOAP 1.1 and 1.2, `BinarySecurityToken` (X509v3 and X509PKIPathv1), direct-reference `SecurityTokenReference`, `wsu:Timestamp`, `AssignID`, and `FindByID`, which returns `ErrAmbiguousID` on a duplicated ID rather than the first match. | [`9756c04`][9756c04] |
| Package `dsig` | XML Signature generation (`Sign` for detached WS-Security signatures, `SignEnveloped` for whole-document ones) and verification with `Coverage`, derived from what each reference actually digested. `ds:SignedInfo` is canonicalized in place in the received tree. Allow-lists are checked before any cryptographic work; XSLT and XPath transforms are refused; `c14n.ErrXML11` and `c14n.ErrRelativeNamespaceURI` surface as `ErrUnverifiable`. RSA PKCS#1 v1.5 and ECDSA (raw `r‖s`) at SHA-256/384/512. | [`9756c04`][9756c04] |
| Package `xenc` | RSA-OAEP key transport with an explicit `xenc11:MGF` and `ds:DigestMethod` (an implicit SHA-1 MGF or digest is refused on decryption), AES-GCM for inline `EncryptedData` and for SwA attachments by `CipherReference`. | [`6debe01`][6debe01] |
| Differential against `xmlsec1` 1.3, `tests/interop` | Signatures (enveloped and detached, RSA and ECDSA, inclusive and exclusive) and encryption, both directions, with a tamper control. In CI through `tests/interop-xmlsec1.sh`, an Alpine container, since xmlsec 1.2 lacks XML Encryption 1.1 `rsa-oaep`. | [`1fe34f8`][1fe34f8] |
| Fuzz targets `FuzzVerify`, `FuzzDecryptEncryptedKey`, `FuzzDecryptData` | Nightly workflow, one hour per target. Mutated signatures are re-signed so reference and transform code is reached, not only the signature check. | [`1fe34f8`][1fe34f8] |
| Error-path tests across every package | Coverage from 47–77% to 96.6–100% per package; tests live beside the source file they exercise. | [`1fe34f8`][1fe34f8] |
| Security assessment and `tests/security` | XXE (every entity, DTD and encoding variant), external fetches at parse and at verification with an authentic signature, key substitution, algorithm confusion, comment truncation and encryption downgrade, each a regression test run on every push. Parse memory and verification cost measured and documented in `docs/security.md`. | [`9279afe`][9279afe] |
| README rewritten for a public reader; runnable examples | It led with internal design-document terms and its examples did not compile. It now says what the library does, lists the supported algorithms and the rules for verifying safely, and its quick start comes from `Example_enveloped` and `Example_wsSecurity`, which `go test` compiles and runs. | [`f2211c5`][f2211c5] |
| Differential against Apache Santuario 4.0.4 | `tests/santuario/Harness.java` drives Santuario; signatures and encryption in both directions, and `SignatureValue` byte equality with Santuario for enveloped (inclusive and exclusive C14N) and WS-Security signatures. `tests/interop.sh` runs both reference implementations in one image. | [`a7e1839`][a7e1839] |
| `staticcheck` and `gosec` in CI | Both clean, versions pinned, no suppressions. | [`a7e1839`][a7e1839] |
| Test data documented | `docs/testing.md` lists every key, document, reference implementation and corpus the tests use, and where each comes from. | [`a7e1839`][a7e1839] |
| WSS4J 4.0.1 in the differential | It processes a WS-Security header built by this library with Basic Security Profile enforcement on, and decrypts our encryption. | [`379ba85`][379ba85] |
| `EncryptedKey.SetKeyInfo`, `EncryptedKey.AddDataReference`, `EncryptOptions.DataID` | Compose an `EncryptedKey` the way a WS-Security receiver finds it: a `ds:KeyInfo` naming the recipient's key, and an `xenc:ReferenceList` naming each `EncryptedData` by its `Id`. Without them WSS4J could not decrypt our output. | [`379ba85`][379ba85] |
| `VerifyOptions.TrustKey` | A callback that sees the signer's key, and certificate when there is one, before any cryptographic or digest work, refusing with `ErrUntrusted`. Closes the pre-trust verification cost found by the security assessment. | [`a5b66ba`][a5b66ba] |
| `VerifyOptions.RequireExplicitCanonicalization` | Refuses a reference relying on the implied Canonical XML 1.0 even when that algorithm is allowed, for profiles that name their canonicalization. | [`ae38a45`][ae38a45] |
| `xmlsec.ParseWithLimits` | Parses under tighter byte, depth and node limits; limits can only be tightened. Exceeding any limit is now `ErrLimitExceeded` from both `Parse` and `ParseWithLimits`. | [`ae38a45`][ae38a45] |
| Golden files, `wss/golden_test.go` | Byte-exact expected output for a signed SOAP envelope with two attachments, a signed-then-encrypted envelope (ciphertext masked, plaintext compared), and two enveloped signatures. Regenerated only with `-update`; LF on every system; a committed test-only key makes them reproducible. | [`c7a3361`][c7a3361] |
| `SignOptions.IDAttributes`, `VerifyOptions.IDAttributes`, extra attributes for `wss.FindByID` | Opt-in extra ID attributes for `"#id"` references, with `dsig.IDAttrSAML` (`ID`) and `dsig.IDAttrDSig` (`Id`), so SAML assertions and XAdES documents can be signed and verified. Duplicate detection spans every counted attribute; the default is unchanged. Santuario interoperates, byte-identical. | [`c6b1e46`][c6b1e46] |
| W3C XML Signature 1.1 interop vectors, `tests/w3c` | 25 third-party vectors in a nested module, so they stay out of the library's module download, with the W3C Document License and notice beside them. Run in CI on all three systems. | [`c37f1e9`][c37f1e9] |
| Raw public keys in `ds:KeyInfo` | `ds:KeyValue` (RSA, and XML Signature 1.1 `ECKeyValue` on P-256/384/521) and `dsig11:DEREncodedKeyValue`, verified and emitted (`KeyInfoKeyValue`, `KeyInfoDEREncodedKeyValue`). `VerifyOptions.PublicKey` pins a raw key; `Coverage.PublicKey` reports the key used, and `Coverage.Certificate` is nil for a raw key. Raw RSA keys under 2048 bits are refused. 10 of the 25 W3C interop vectors now verify. | [`d39fb55`][d39fb55] |
| SwA signature transforms and Attachment-Complete encryption | `TransformAttachmentContentSignature` and `TransformAttachmentCompleteSignature`, with the SwA profile's MIME header and content canonicalization (section 5.4), and Attachment-Complete encryption. Interoperable with WSS4J in both directions for both. | [`83a4f89`][83a4f89] |
| `SignOptions.Parent`: in-place signing | XML Signature allows any canonicalization of `ds:SignedInfo`, but a detached signature is canonicalized before it is placed, so `Sign` refused inclusive canonicalization. With `Parent` set, the signature is appended first and computed where it stands, so every canonicalization works; Santuario verifies an in-place inclusive signature. Closes a drift from the XML Signature specification. | [`dd64026`][dd64026] |
| XML Signature 1.1 conformance | Refuses RSA signing keys under 2048 bits and non-NCName ids; the base64 transform over a node set; octets parsed into a node set before a canonicalization; `#xpointer(/)` and `#xpointer(id('…'))` keeping comments; same-document `KeyInfoReference`; `VerifyOptions.ResolveOmittedURI` and `Coverage.OmittedURISigned`; a pinned key ignores an unsupported `KeyInfo`. Allow-lists default to a named default set. | [`4c0b0c5`][4c0b0c5] |
| XML Encryption 1.1 conformance | `cid:` URIs escaped; NFC plaintext (`ErrNotNFC`); NCName ids; `xmlns=""` kept on encrypted elements; strict `EncryptionMethod`; `CipherReference` transforms checked, and same-document `CipherReference` with base64; `FindEncryptedKey`; `EncryptContent`; `EncryptHeader` (`wsse11:EncryptedHeader`); AES key wrap and ECDH-ES with ConcatKDF, interoperable with xmlsec1 and Santuario; generic decryption errors. Breaking: `EncryptedKey.AddDataReference` returns an error. | [`7d59007`][7d59007] |
| WS-Security 1.1.1 conformance | `Header.Prepend` and processing-order placement, so sign-then-encrypt is accepted by WSS4J; SOAP attributes namespaced on default-namespace envelopes; `wsse11:TokenType`; ds/xenc elements get their own `Id`; one timestamp; `ParseTimestamp` and `Timestamp.Check` (`ErrMessageExpired`); key identifier and issuer-serial references; `ResolveSecurityTokenReferenceStrict`, `MatchSecurityTokenReference`, and `VerifyOptions.StrictSecurityTokenReference`. | [`091298e`][091298e] |
| Legacy XML Signature algorithms, verification only | SHA-1 digest, RSA-SHA1, DSA-SHA1 with `DSAKeyValue`, HMAC-SHA1/256/384/512, as the specification requires; accepted only when named in an allow-list, never produced by `Sign`. `VerifyOptions.HMACKey` is the only HMAC key; `HMACOutputLength` is checked against CVE-2009-0217. An allow-list naming an unimplemented algorithm no longer panics. | [`b3ad29a`][b3ad29a] |
| Legacy XML Encryption algorithms, decryption only | AES-CBC, 3DES, `rsa-oaep-mgf1p` and SHA-1 OAEP digest/MGF, RSA v1.5 (`xenc.DecryptEncryptedKeyPKCS1v15`, implicit rejection), and `kw-tripledes` unwrap; accepted only when named, never produced. CBC failures share one error and a constant-time padding check. | [`3cb030f`][3cb030f] |
| Versioning, CI and release workflow | `internal/version.Version` as the source of truth, checked against this file on every CI run and against the tag on release. CI on Linux, macOS and Windows; hygiene checks for `peppol` imports and strings. | [`2281ef3`][2281ef3] |

### Fixed

| Change | Problem → solution | Commit |
|---|---|---|
| 13 exported functions panicked on a nil argument | Found by the security assessment. A caller passing on a failed lookup from a hostile message (no `EncryptedKey`, no token) crashed rather than got an error. Every exported function now returns an error for nil or wrong-kind input. | [`9279afe`][9279afe] |
| `Exclusive10WithComments` transform always failed | The plain algorithm was derived by trimming `#WithComments` from the URI, which leaves `…xml-exc-c14n` where the plain URI is `…xml-exc-c14n#`, so signing or verifying such a reference failed with an unsupported algorithm. Found by the error-path tests. The plain form now comes from an explicit map of `c14n` constants, and the ECDSA check from an explicit set of `Sig*` constants: no algorithm URI is derived from strings. | [`1fe34f8`][1fe34f8] |
| A failed `NewHeader`, `AddBinarySecurityToken` or `AddTimestamp` left a half-built element in the document | The element was attached before a namespace check that could fail. Each is now built detached, declares its own prefix and is attached last, so a `wsu` or `wsse` prefix bound elsewhere in the document is no longer an error at all. | [`1fe34f8`][1fe34f8] |
| `TestEncryptElement` was flaky | It asserted the output did not contain `hi`, which random base64 ciphertext sometimes does. Found by the fuzzing run. | [`1fe34f8`][1fe34f8] |

### Changed

| Change | Why | Commit |
|---|---|---|
| **Breaking:** API review before v1 | `xenc`'s positional allow-list arguments become one `xenc.DecryptOptions`, named like `dsig.VerifyOptions`, so a future option is not a breaking change. The namespace constants, `TransformAttachmentCiphertext`, `DigestSHA384XMLEnc` and `ErrNotNFC` move to the root package, where each is defined once (`NSDSig` was in both `dsig` and `xenc`). `KeyInfoSpec` becomes `KeyInfoForm`, the name of the `Coverage` field it reports. `wss.FindByIDAttributes` folds into a variadic `wss.FindByID`. `Attachment.MIMEHeaders` is a `textproto.MIMEHeader`. Removed: the unused `KeyProvider.Decrypter` and `Chain`, and `SignatureHash`, `DigestHash` and `MGFHash`, now internal. | [`7a8061b`][7a8061b] |
| **Breaking:** `#Attachment-Content-Only` and `#Attachment-Complete` are refused as signature transforms | They are the SwA profile's `EncryptedData` Type URIs. WSS4J refuses them in a signature, so attachment signatures made with them were rejected by every WS-Security peer. Sign attachments with `TransformAttachmentContentSignature`. | [`e4c7509`][e4c7509] |
| **Breaking:** `xenc.DecryptAttachment` returns `*xmlsec.Attachment` | Attachment-Complete decryption restores the MIME headers along with the body. | [`83a4f89`][83a4f89] |
| Verification completes a reference that ends in a node set with Canonical XML 1.0 | XML-DSig 4.4.3.2 requires it, and a corpus of 122 real Peppol SMP responses showed 118 rely on it: before this, 60 of 62 SMP providers' signatures were refused. The implied algorithm is checked against the caller's allow-list. Signing still never relies on it. | [`cc53cf7`][cc53cf7] |
| `ds:X509Data` may carry `X509SubjectName`, `X509IssuerSerial` and `X509SKI` beside its one certificate | 107 of the same responses carry them. They are ignored; the key always comes from the certificate. With both changes, all 122 SMP responses verify. | [`cc53cf7`][cc53cf7] |
| An HMAC signature method is reported as `ErrAlgorithmNotAllowed` | It was reported as malformed, because its `HMACOutputLength` child was checked before the allow-list. | [`cc53cf7`][cc53cf7] |
| Unreachable error branches deleted | `crypto/rand.Read` never returns an error since Go 1.24; a detached element's own namespace declaration cannot conflict, so `wss` declares it directly; a hand-written `indexOf` is `slices.Index`. | [`169fc0c`][169fc0c] |
| 100% statement coverage, enforced in CI | `aes.NewCipher` now runs before the algorithm's size check, so both are reachable. `dsig.Verify` canonicalizes each `ds:Reference` for `Coverage.Raw` before `ds:SignedInfo`, so each failure point has an input that reaches it. | [`e90defe`][e90defe] |
| Minimum Go is 1.26, not 1.25 | `rsa.EncryptOAEPWithOptions`, the only standard-library route to an OAEP digest and MGF1 hash that differ, arrived in Go 1.26. | [`6debe01`][6debe01] |

[9756c04]: https://github.com/knroy/go-xmlsec/commit/9756c04
[6debe01]: https://github.com/knroy/go-xmlsec/commit/6debe01
[2281ef3]: https://github.com/knroy/go-xmlsec/commit/2281ef3
[169fc0c]: https://github.com/knroy/go-xmlsec/commit/169fc0c
[1fe34f8]: https://github.com/knroy/go-xmlsec/commit/1fe34f8
[9279afe]: https://github.com/knroy/go-xmlsec/commit/9279afe
[f2211c5]: https://github.com/knroy/go-xmlsec/commit/f2211c5
[a7e1839]: https://github.com/knroy/go-xmlsec/commit/a7e1839
[379ba85]: https://github.com/knroy/go-xmlsec/commit/379ba85
[a5b66ba]: https://github.com/knroy/go-xmlsec/commit/a5b66ba
[ae38a45]: https://github.com/knroy/go-xmlsec/commit/ae38a45
[c7a3361]: https://github.com/knroy/go-xmlsec/commit/c7a3361
[c6b1e46]: https://github.com/knroy/go-xmlsec/commit/c6b1e46
[c37f1e9]: https://github.com/knroy/go-xmlsec/commit/c37f1e9
[d39fb55]: https://github.com/knroy/go-xmlsec/commit/d39fb55
[83a4f89]: https://github.com/knroy/go-xmlsec/commit/83a4f89
[dd64026]: https://github.com/knroy/go-xmlsec/commit/dd64026
[4c0b0c5]: https://github.com/knroy/go-xmlsec/commit/4c0b0c5
[7d59007]: https://github.com/knroy/go-xmlsec/commit/7d59007
[091298e]: https://github.com/knroy/go-xmlsec/commit/091298e
[b3ad29a]: https://github.com/knroy/go-xmlsec/commit/b3ad29a
[3cb030f]: https://github.com/knroy/go-xmlsec/commit/3cb030f
[7a8061b]: https://github.com/knroy/go-xmlsec/commit/7a8061b
[e4c7509]: https://github.com/knroy/go-xmlsec/commit/e4c7509
[cc53cf7]: https://github.com/knroy/go-xmlsec/commit/cc53cf7
[e90defe]: https://github.com/knroy/go-xmlsec/commit/e90defe
[13a61dc]: https://github.com/knroy/go-xmlsec/commit/13a61dc
[57349cb]: https://github.com/knroy/go-xmlsec/commit/57349cb
[bec715d]: https://github.com/knroy/go-xmlsec/commit/bec715d
[6736ffd]: https://github.com/knroy/go-xmlsec/commit/6736ffd
[1eb3aaa]: https://github.com/knroy/go-xmlsec/commit/1eb3aaa
[51d76cc]: https://github.com/knroy/go-xmlsec/commit/51d76cc
[11aa01d]: https://github.com/knroy/go-xmlsec/commit/11aa01d
[bf72db6]: https://github.com/knroy/go-xmlsec/commit/bf72db6
[996144a]: https://github.com/knroy/go-xmlsec/commit/996144a
[caaf44e]: https://github.com/knroy/go-xmlsec/commit/caaf44e
[7a6a367]: https://github.com/knroy/go-xmlsec/commit/7a6a367
[cf8c78b]: https://github.com/knroy/go-xmlsec/commit/cf8c78b
[cb813c1]: https://github.com/knroy/go-xmlsec/commit/cb813c1
[afb42a1]: https://github.com/knroy/go-xmlsec/commit/afb42a1
[663bfe5]: https://github.com/knroy/go-xmlsec/commit/663bfe5
[57683c8]: https://github.com/knroy/go-xmlsec/commit/57683c8
[ddea0d6]: https://github.com/knroy/go-xmlsec/commit/ddea0d6
[1146d94]: https://github.com/knroy/go-xmlsec/commit/1146d94
[7e0f8aa]: https://github.com/knroy/go-xmlsec/commit/7e0f8aa
[126f886]: https://github.com/knroy/go-xmlsec/commit/126f886
[f320ad2]: https://github.com/knroy/go-xmlsec/commit/f320ad2
[feb2a92]: https://github.com/knroy/go-xmlsec/commit/feb2a92
[94c506f]: https://github.com/knroy/go-xmlsec/commit/94c506f
[391978c]: https://github.com/knroy/go-xmlsec/commit/391978c
[fcf935d]: https://github.com/knroy/go-xmlsec/commit/fcf935d
[7483b9f]: https://github.com/knroy/go-xmlsec/commit/7483b9f
[040dd04]: https://github.com/knroy/go-xmlsec/commit/040dd04
[38e44ca]: https://github.com/knroy/go-xmlsec/commit/38e44ca
[7bfc182]: https://github.com/knroy/go-xmlsec/commit/7bfc182
[be398ff]: https://github.com/knroy/go-xmlsec/commit/be398ff
[97b8da3]: https://github.com/knroy/go-xmlsec/commit/97b8da3
[8baed7c]: https://github.com/knroy/go-xmlsec/commit/8baed7c
[be0430c]: https://github.com/knroy/go-xmlsec/commit/be0430c
[dc5b096]: https://github.com/knroy/go-xmlsec/commit/dc5b096
[5489f85]: https://github.com/knroy/go-xmlsec/commit/5489f85
