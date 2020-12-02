Encode and decode address using the bech32 address scheme.

```
go run examples/bech32/main.go decode -address iota1q9f0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryj0w6qwt

==> Bech32 Address Decoder
  bech32 (64-char):     iota1q9f0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryj0w6qwt
  network (4-char):     iota
  version (1-byte):     1 (Ed25519)
  hash (64-char):       52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649
  addr bytes (33-byte): 0152fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649

go run examples/bech32/main.go encode -hash=52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649 -prefix=atoi

==> Bech32 Address Encoder
  hash (64-char):       52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649
  addr bytes (33-byte): 0152fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649
  network (4-char):     atoi
  version (1-byte):     1 (Ed25519)
  bech32 (64-char):     atoi1q9f0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryjgqtp5x
    checksum                                                                      ^^^^^^

go run examples/bech32/main.go encode -hash=EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9

==> Bech32 Address Encoder
  hash (81-char):       EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9
  addr bytes (49-byte): 0002f99349fcafafdf7512f7d654fc3ed96e24fa4f0005d09c9aa97ce12a77391e38c2064bb2ae8e073ef3f0a4fe00338c
  network (4-char):     iota
  version (1-byte):     0 (WOTS)
  bech32 (90-char):     iota1qqp0ny6fljh6lhm4ztmav48u8mvkuf86fuqqt5yun25hecf2wuu3uwxzqe9m9t5wqul08u9ylcqr8rqeyhqa2
    checksum                                                                                                ^^^^^^
```
