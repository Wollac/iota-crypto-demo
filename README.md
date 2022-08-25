# Crypto demo
This repository contains Go example implementations related to several cryptographic constructs used in various DLTs.

## Packages
It contains the following general packages:
- `slip10` implements the [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) private key derivation with full [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatibility.
- `bip32path` provides utilities for [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) chains.
- `bip39` implements the [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) specification and mnemonic [word lists](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md).
- `bech32` implements Bech32 addresses based on the format described in [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
- `ed25519` implements Ed25519 signatures with particular validation rules around edge cases as described in [ZIP-215](https://zips.z.cash/zip-0215).
- `curl` implements the Curl ternary hash function in its batched mode. It relies on [`avo`](https://github.com/mmcloughlin/avo) to generate high-performance x86 assembly.
- `merkle` implements a simple Merkle tree hash.
- `pow` implements the Curl-based proof of work for arbitrary binary data as mentioned in [TIP-12](https://iotaledger.github.io/tips/tips/TIP-0012/tip-0012.html).
- `encoding/b1t6` implements the binary-to-ternary encoding which uses 6 trits to represent each byte.
- `encoding/b1t8` implements the binary-to-ternary encoding which uses 8 trits to represent each byte.
- `migration` implements the migration address computation as described in this document: https://hackmd.io/@wollac/H1tZoCK0w

All these packages are tested against the full test vectors provided in the corresponding specifications.

## Examples
- `bech32` encode and decode addresses using the bech32 address scheme.<br>
Run the example with `go run examples/bech32/main.go` and use `-help` to see the available commands.
- `kdf` shows the private and public key derivation using SLIP-10 and BIP-39 mnemonics + passphrase.<br>
It performs the legacy IOTA seed derivation (as implemented in the Ledger App) based on BIP-32 and the Ed25519 key derivation following SLIP-10.<br>
Run with `go run examples/kdf/main.go` and use `-help` to see the available command-line flags.
- `merkle` prints the Merkle tree of several random transaction hashes on the console.<br>
Run with `go run examples/merkle/main.go` and use `-help` to see the available command-line flags.
- `mnemseed` presents the extension of BIP-0039 to decode and encode 81-tryte legacy IOTA seeds using mnemonics.<br>
Run with `go run examples/mnemseed/main.go` and use `-help` to see the available command-line flags.
