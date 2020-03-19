# IOTA crypto demo
This repository contains Go example implementations related to the cryptography RFCs in [iotaledger/protocol-rfcs](https://github.com/iotaledger/protocol-rfcs).

## Packages
It contains the following general packages:
- `bip32path` provides utilities for [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) chains.
- `bip39` implements the [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) specification and mnemonic [word lists](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md).
- `slip10` implements the [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) private key derivation.
- `ed25519` provides utilities to generate and verify transaction bundles using the [Ed25519](https://ed25519.cr.yp.to/) signature scheme as described in the IOTA protocol [RFC-0009 draft](https://github.com/iotaledger/protocol-rfcs/pull/9).

All these packages are tested against the full test vectors provided in the corresponding specifications.

## Examples
- `ed25519` creates bundles using the Ed25519 signature scheme with varying number of input transactions and one output transaction.<br>
Run the example with `go run examples/ed25519/main.go` and use `-help` to see the available command-line flags.
- `kdf` shows the private and public key derivation using SLIP-0010 and BIP-0039 mnemonics + passphrase.<br>
It performs the legacy IOTA seed derivation (as implemented in the Ledger App) based on BIP-0032 and the Ed25519 key derivation following SLIP-0010.
Run with `go run examples/kdf/main.go` and use `-help` to see the available command-line flags.
- `mnemseed` presents the extention of BIP-0039 to decode and encode 81-tryte legacy IOTA seeds using mnemonics.
Run with `go run examples/mnemseed/main.go` and use `-help` to see the available command-line flags.
