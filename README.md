# IOTA crypto demo
This repository contains Go example implementations related to the cryptography RFCs in [iotaledger/protocol-rfcs](https://github.com/iotaledger/protocol-rfcs).

## Packages
It contains the following general packages:
- `encoding/b1t6` implements the binary-to-ternary encoding as described in the IOTA protocol [RFC-0015](https://github.com/iotaledger/protocol-rfcs/blob/master/text/0015-binary-to-ternary-encoding/0015-binary-to-ternary-encoding.md).
- `bech32` implements Bech32 addresses based on the format described in [RFC-0020 draft](https://github.com/iotaledger/protocol-rfcs/pull/20). 
- `bip32path` provides utilities for [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) chains.
- `bip39` implements the [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) specification and mnemonic [word lists](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md).
- `ed25519` implements Ed25519 signatures with particular validation rules around edge cases as described in [RFC-0028 draft](https://github.com/iotaledger/protocol-rfcs/pull/28).
- `merkle` implements the combination of multiple bundle hashes into one Merkle tree as described in the IOTA protocol [RFC-0012](https://github.com/iotaledger/protocol-rfcs/blob/master/text/0012-milestone-merkle-validation/0012-milestone-merkle-validation.md).
- `pow` implements the Curl-based proof of work for arbitrary binary data as mentioned in [RFC-0017 draft](https://github.com/iotaledger/protocol-rfcs/pull/17).
- `slip10` implements the [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) private key derivation.

All these packages are tested against the full test vectors provided in the corresponding specifications.

## Examples
- `bech32` encode and decode addresses using the bech32 address scheme.<br>
Run the example with `go run examples/bech32/main.go` and use `-help` to see the available commands.
- `kdf` shows the private and public key derivation using SLIP-0010 and BIP-0039 mnemonics + passphrase.<br>
It performs the legacy IOTA seed derivation (as implemented in the Ledger App) based on BIP-0032 and the Ed25519 key derivation following SLIP-0010.<br>
Run with `go run examples/kdf/main.go` and use `-help` to see the available command-line flags.
- `merkle` prints the Merkle tree of several random transaction hashes on the console.<br>
Run with `go run examples/merkle/main.go` and use `-help` to see the available command-line flags.
- `mnemseed` presents the extension of BIP-0039 to decode and encode 81-tryte legacy IOTA seeds using mnemonics.<br>
Run with `go run examples/mnemseed/main.go` and use `-help` to see the available command-line flags.
