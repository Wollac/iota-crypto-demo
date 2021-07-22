Derive private and public keys using SLIP-0010 key derivation and BIP-0039 mnemonics.

```
go run examples/kdf/main.go -path "44'/4218'/1'/0'"

==> Key Derivation Parameters
 entropy (16-byte):     00000000000000000000000000000000
 mnemonic (12-word):    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
 optional passphrase:   ""
 master seed (64-byte): 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4

==> Legacy IOTA Seed Derivation (Ledger App)
 SLIP-10 curve seed:    Bitcoin seed
 SLIP-10 address path:  m/44'/4218'/1'/0'
 private key (32-byte): dc63c0f6c149de0259272a5251cc2ce98ffd920ccecb192eb3088567b91c04f0
 chain code (32-byte):  f0fcfb01cc627ceeedc9f4e2bb0149f4a57910d3a577ed9223c15fca4327912d
 IOTA seed (81-tryte):  GKGUFIVGUUC9YTKNO9AKNTIJJHSGWHSLXLAYWOCI9EURIWKFDKEAISSZKHLHCYZGC9HOQPX9FJAZWEYAZ

==> Ed25519 Private Key Derivation
 SLIP-10 curve seed:    ed25519 seed
 SLIP-10 address path:  m/44'/4218'/1'/0'
 private key (32-byte): 92703a050b014626ff700dd4ca8701c6b0f6fd07947e6185c7a9fbd5ace0cc59
 chain code (32-byte):  974c2e2c01f8d2a9eabbb805f9222716056bea5ac91353599c190c9f1dae243f
 address (64-char):     iota1qp22n849vywq9aayajl9utpfawlhjaskqfdzhphevsr4g5lt74mhckpnacr
```
