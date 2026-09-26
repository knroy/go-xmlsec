# TODO

Open work against the specifications this library implements: W3C XML
Signature 1.1, W3C XML Encryption 1.1, OASIS SOAP Message Security 1.1.1, the
OASIS X.509 Token Profile 1.1.1 and SwA Profile 1.1.1, and the WS-I Basic
Security Profile 1.1.

## Required and not met

None. Every MUST and every REQUIRED algorithm of these specifications is
implemented. The weak algorithms among them are verification- and
decryption-only opt-ins.

## Recommended or optional, not implemented

None. The XPath, XPath Filter 2.0 and XSLT transforms, `http:` dereferencing
(through a caller-supplied resolver), PKCS7 tokens, finite-field `dh-es` and
`dh`, and PBKDF2 are implemented as opt-ins; see
[security.md](security.md#conformance).

## Deliberately not met

| Item | Level | Why not |
|---|---|---|
| Basic Security Profile R5620 and R5621 algorithm lists | MUST in BSP 1.1 | They admit only CBC, 3DES, `rsa-1_5` and `rsa-oaep-mgf1p`; this library produces AES-GCM and XML Encryption 1.1 RSA-OAEP, which WSS4J accepts, and decrypts the listed ones as opt-ins. Producing them would contradict the rule that weak algorithms are never produced. |
