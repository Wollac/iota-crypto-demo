Encode and decode address using the bech32 address scheme.

```
go run examples/bech32/main.go decode -address iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx

==> Bech32 Address Decoder
  bech32 (64-char):     iota1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6xqgyzyx
  network (4-char):     iota
  version (1-byte):     0 (Ed25519)
  hash (64-char):       efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3
  addr bytes (33-byte): 00efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3

go run examples/bech32/main.go encode -key=6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8 -prefix=atoi

==> Bech32 Address Encoder
  public key (32-byte): 6f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8
  hash (64-char):       efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3
  addr bytes (33-byte): 00efdc112efe262b304bcf379b26c31bad029f616ee3ec4aa6345a366e4c9e43a3
  network (4-char):     atoi
  version (1-byte):     0 (Ed25519)
  bech32 (64-char):     atoi1qrhacyfwlcnzkvzteumekfkrrwks98mpdm37cj4xx3drvmjvnep6x8x4r7t
    checksum                                                                      ^^^^^^
```
