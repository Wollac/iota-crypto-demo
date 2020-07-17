Encode and decode address using the bech32 address scheme.

```
go run examples/bech32/main.go encode -hash=EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9

==> Bech32 Address Encoder
  hash (81-char):       EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9
  network (3-char):     iot
  version (1-byte):     0 (WOTS)
  address (90-char):    iot1qr4r3j4wamzu8ltdp6y7xtysj77vqtwua3q23hx9zmrmcqfdpd4muv25jwctsmxlh5g60w8s6k4x7gsq28c8da
    checksum                                                                                                ^^^^^^

go run examples/bech32/main.go decode -address iot1q9f0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryjtzcp98

==> Bech32 Address Decoder
  address (63-char):    iot1q9f0mlq8yxpx2nck8a0slxnzr4ef2ek8f5gqxlzd0wasgp73utryjtzcp98
  network (3-char):     iot
  version (1-byte):     1 (Ed25519)
  hash (64-char):       52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649
```
