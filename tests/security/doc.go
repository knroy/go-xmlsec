// Package security holds regression tests for attacks on the library as a
// whole: XXE and every other route by which a document could make the
// library read a file or reach the network, and transform programs a
// caller did not allow, and decryption: Basic Security Profile refusals
// before any key is used, and one generic error for every failure. See
// docs/security.md.
package security
