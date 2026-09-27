# TODO

Open work against the specifications this library implements: W3C XML
Signature 1.1, W3C XML Encryption 1.1, OASIS SOAP Message Security 1.1.1, the
OASIS X.509 Token Profile 1.1.1 and SwA Profile 1.1.1, and the WS-I Basic
Security Profile 1.1.

## Required and not met

None but the Basic Security Profile's R5620 and R5621 algorithm lists,
deliberately not met (below). Every other MUST and every REQUIRED algorithm
of these specifications is implemented. The weak algorithms among them are
verification- and decryption-only opt-ins.

## Recommended or optional, not implemented

None. A clause-by-clause audit of every specification above found 55 gaps
after v1.0.0; all are implemented, as opt-ins where they widen what is
accepted. See [security.md](security.md#conformance) and the changelog.

## Deliberately not met

| Item | Level | Why not |
|---|---|---|
| Basic Security Profile R5620 and R5621 algorithm lists | MUST in BSP 1.1 | They admit only CBC, 3DES, `rsa-1_5` and `rsa-oaep-mgf1p`; this library produces AES-GCM and XML Encryption 1.1 RSA-OAEP, which WSS4J accepts, and decrypts the listed ones as opt-ins. Producing them would contradict the rule that weak algorithms are never produced. |
| Producing SHA-1, RSA-SHA1, DSA, ECDSA-SHA1, HMAC-SHA1, CBC, 3DES, `rsa-1_5`, `rsa-oaep-mgf1p`, `kw-tripledes` | DISCOURAGED or required for interoperability | Verified and decrypted as opt-ins, never produced. |
| `PGPData`, `SPKIData` (XML Signature §4.5.5, §4.5.6) | OPTIONAL | No key or trust model for them in the Go standard library. |
| `MgmtData` (§4.5.7) | NOT RECOMMENDED | The specification says it SHOULD NOT be used. |
| Explicit `ECParameters` and the RFC 4050 `ECDSAKeyValue` (§4.5.2.3) | OPTIONAL | Attacker-chosen curve parameters; the named curves are supported. |
| XSLT and XPath Filter 2.0 on an `xenc:CipherReference` | OPTIONAL | XSLT would run the sender's program before anything is authenticated. Selecting the ciphertext needs neither: the XPath transform of Example 13 is implemented, as an allow-listed opt-in. |
| PBKDF2 `OtherSource` salt (XML Encryption §5.4.2) | OPTIONAL | RFC 8018 defines no salt source algorithm: there is nothing to implement. |
| EXI `EncryptedData` Type | OPTIONAL | Needs an EXI codec; the octets are returned, as §4.2 asks for an unknown Type. |
| W3C vector AGRMNT.9 (ECDH-ES with PBKDF2) | Test vector | Its producer encoded the shared secret in a way the specification does not define; xmlsec1's own suite omits it. |
| Other token profiles (UsernameToken, SAML, Kerberos, REL) | Separate specifications | Out of scope. |
