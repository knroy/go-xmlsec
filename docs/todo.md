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

These are decisions rather than open work; each is refused or omitted for the
reason given in [security.md](security.md#conformance), and is listed here
only so that a future change of mind has a place to start.

| Item | Level | Why not |
|---|---|---|
| XPath and XPath Filter 2.0 transforms | RECOMMENDED (XML Signature §6.1) | Evaluate attacker-supplied expressions during verification. |
| Dereferencing `http:` URIs | RECOMMENDED (XML Signature §4.4.3.1) | A server-side request forgery surface. |
| XSLT transform | OPTIONAL | Executes attacker-supplied code. |
| PKCS7 token type | OPTIONAL (X.509 Token Profile) | PKIPath is the profile's recommended chain form. |
| Finite-field `dh-es`, PBKDF2 | OPTIONAL (XML Encryption §5) | Not needed; ECDH-ES and key transport cover key establishment. |
| Basic Security Profile R5620 and R5621 algorithm lists | MUST in BSP 1.1 | They admit only CBC, 3DES, `rsa-1_5` and `rsa-oaep-mgf1p`; this library produces AES-GCM and XML Encryption 1.1 RSA-OAEP, which WSS4J accepts, and decrypts the listed ones as opt-ins. |
