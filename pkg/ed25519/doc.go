/*
Package ed25519 provides utilities to generate and verify transactions using
Ed25519 signature scheme as described in the IOTA protocol RFC-0009.

The sub-packages are organized in a very similar fashion as used in the
github.com/iotaledger/iota.go library.

For the actual signature algorithm the Ed25519 implementation in crypto/ed25519
of the Go stdlib is used. It is important to note that, unlike the RFC's
formulation, this package's private key representation includes a public key
suffix to make multiple signing operations with the same key more efficient.
The crypto/ed25519 package refers to the RFC private key as the “seed”.
*/
package ed25519
