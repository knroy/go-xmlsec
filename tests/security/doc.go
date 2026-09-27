// Package security holds regression tests for attacks on the library as a
// whole: XXE and every other route by which a document could make the
// library read a file or reach the network; transform programs a caller did
// not allow; signature wrapping, key substitution, key descriptions and key
// resolvers; algorithm confusion and downgrade, including Diffie-Hellman and
// PBKDF2 parameters; and, on decryption, Basic Security Profile refusals
// before any key is used and one generic error for every failure. See
// docs/security.md.
package security
