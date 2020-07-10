Encode and decode address using the bech32 address scheme.

```
go run examples/bech32/main.go encode -hash=EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9DGCJRJTHZ

==> Bech32 Address Encoder
  hash (90-char):       EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9DGCJRJTHZ
  network (4-byte):     iota
  version (1-byte):     WOTS
  address (90-byte):    iota1qqp0ny6fljh6lhm4ztmav48u8mvkuf86fuqqt5yun25hecf2wuu3uwxzqe9m9t5wqul08u9ylcqr8rqeyhqa2
    HRP                 ^^^^
    separator               ^
    checksum                                                                                                ^^^^^^

go run examples/bech32/main.go decode -addr iota1qqp0ny6fljh6lhm4ztmav48u8mvkuf86fuqqt5yun25hecf2wuu3uwxzqe9m9t5wqul08u9ylcqr8rqeyhqa2

==> Bech32 Address Decoder
  address (90-byte):    iota1qqp0ny6fljh6lhm4ztmav48u8mvkuf86fuqqt5yun25hecf2wuu3uwxzqe9m9t5wqul08u9ylcqr8rqeyhqa2
  network (4-byte):     iota
  version (1-byte):     WOTS
  hash (81-tryte):      EQSAUZXULTTYZCLNJNTXQTQHOMOFZERHTCGTXOLTVAHKSA9OGAZDEKECURBRIXIJWNPFCQIOVFVVXJVD9
```
```
go run examples/bech32/main.go encode -hash=0f56da52d7118be49829dba6b10954052b087e2137d3b259a4f3343ef4420264

==> Bech32 Address Encoder
  hash (64-char):       0f56da52d7118be49829dba6b10954052b087e2137d3b259a4f3343ef4420264
  network (4-byte):     iota
  version (1-byte):     Ed25519
  address (64-byte):    iota1qy84dkjj6ugcheyc98d6dvgf2szjkzr7yyma8vje5neng0h5ggpxgz88uep
    HRP                 ^^^^
    separator               ^
    checksum                                                                      ^^^^^^

go run examples/bech32/main.go decode -addr iota1qy84dkjj6ugcheyc98d6dvgf2szjkzr7yyma8vje5neng0h5ggpxgz88uep

==> Bech32 Address Decoder
  address (64-byte):    iota1qy84dkjj6ugcheyc98d6dvgf2szjkzr7yyma8vje5neng0h5ggpxgz88uep
  network (4-byte):     iota
  version (1-byte):     Ed25519
  hash (32-tryte):      0f56da52d7118be49829dba6b10954052b087e2137d3b259a4f3343ef4420264
```
