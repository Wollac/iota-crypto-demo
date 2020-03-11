Create bundles using the Ed25519 signature scheme as described in RFC-0009.

```
go run examples/ed25519/main.go -inputs 2 -timestamp 0

==> Bundle Parameters
 Output
  address (81-tryte):   999999999999999999999999999999999999999999999999999999999999999999999999999999999
  tag (27-tryte):       EDTWOFIVEFIVEONENINE
  bundle timestamp:     1970-01-01 01:00:00 +0100 CET
 Input #1:
  private key (32-byte):628b484a59c375aab1c01f2c326062160813be402daafa9fe773e4ac6795ca2a
  public key (32-byte): 8290f3c033848f20055d086f96a8fb8f021730b5729eda50bc601fec61a80775
  pubkey hash (48-byte):ad96c502ebd897c4d38f13ad241eb7e08cd1ea9ce20a59e794df6adc37e49696a5f2bbf8404dfbc564e506f9dc0d1290
  address (81-tryte):   RPBDRWXCLCEJNFCGDDTTWASWFENRSMDYHJOADUKBXOGLGRRGIQHKNNOTHYCJ9UCUKALCMCXCGPIWTOZBW
 Input #2:
  private key (32-byte):f2485ab0f0d8c58848e2bd52db0e43a5dcfdd234206e76a7a801ea49ba2a11ed
  public key (32-byte): 3c74b6ab117c2d47a4459b64baffbdacb143875c6a63f4465368f562c2220f00
  pubkey hash (48-byte):47a12a6ec0ef521d195c8db62898d82c203b5acb6b0d18b3d838f2e00b10ea68406b6015df64cd3b905256ff4b421bb0
  address (81-tryte):   EDZVXPAIZJF9QSBWZWZQEBYJQXZAXHBXGFVOJBSDVGKYFBRLQLEXINEUG9CMNOQHLYKMRNTZQRKMRWEKC

==> Signed Bundle
[
 {
  "hash": "",
  "signatureMessageFragment": "",
  "address": "999999999999999999999999999999999999999999999999999999999999999999999999999999999",
  "value": 1000000000,
  "obsoleteTag": "EDTWOFIVEFIVEONENINE",
  "timestamp": 0,
  "currentIndex": 0,
  "lastIndex": 2,
  "bundle": "OSESUGBPJEJFRTQWOMEJZXAWADGPLFJZIVDDICWCYYMROQWNJCPVOQSU9HKINJVRXKGJJHNZAAEHRXAL9",
  "trunkTransaction": "",
  "branchTransaction": "",
  "tag": "EDTWOFIVEFIVEONENINE",
  "attachmentTimestamp": 0,
  "attachmentTimestampLowerBound": 0,
  "attachmentTimestampUpperBound": 0,
  "nonce": ""
 },
 {
  "hash": "",
  "signatureMessageFragment": "IVWWN9QYXBKVVWEAE9LCH9CDBWTXV9VWB9WAUBFXFDJWPZZCMXODDAGZPDTXG9ID9DRYUWQCQZBXZBSBGZVBHWA9ZWV9MZPXU9ZCLDN9I9KBAWKACCID9CWBAXZZHYGZWXYCFBXDMWFZRXRXG9K9ACNDABSBAWIAC9CYLDL9WAQWXAZCEYYYHYKCEYHYGZH",
  "address": "RPBDRWXCLCEJNFCGDDTTWASWFENRSMDYHJOADUKBXOGLGRRGIQHKNNOTHYCJ9UCUKALCMCXCGPIWTOZBW",
  "value": -500000000,
  "obsoleteTag": "",
  "timestamp": 0,
  "currentIndex": 1,
  "lastIndex": 2,
  "bundle": "OSESUGBPJEJFRTQWOMEJZXAWADGPLFJZIVDDICWCYYMROQWNJCPVOQSU9HKINJVRXKGJJHNZAAEHRXAL9",
  "trunkTransaction": "",
  "branchTransaction": "",
  "tag": "",
  "attachmentTimestamp": 0,
  "attachmentTimestampLowerBound": 0,
  "attachmentTimestampUpperBound": 0,
  "nonce": ""
 },
 {
  "hash": "",
  "signatureMessageFragment": "FBHDGXWXQAPERBQCPXOCGWSDKXZ9NYXXBXMBNWKCYDRDO9PCBCWDP9QDSYGAOA99XYIYMZD9HAJAG9JX9WBXCDGVIBQXFDWBJDTWJAIZJZFCTAOEWDG9HWWZWZWCDXIDOCJAOBTXJXSEXZDANYCZXD9APXNXTDP9YYPDZBDAWWW9NALBIZDWDYBBFXADIWC",
  "address": "EDZVXPAIZJF9QSBWZWZQEBYJQXZAXHBXGFVOJBSDVGKYFBRLQLEXINEUG9CMNOQHLYKMRNTZQRKMRWEKC",
  "value": -500000000,
  "obsoleteTag": "",
  "timestamp": 0,
  "currentIndex": 2,
  "lastIndex": 2,
  "bundle": "OSESUGBPJEJFRTQWOMEJZXAWADGPLFJZIVDDICWCYYMROQWNJCPVOQSU9HKINJVRXKGJJHNZAAEHRXAL9",
  "trunkTransaction": "",
  "branchTransaction": "",
  "tag": "",
  "attachmentTimestamp": 0,
  "attachmentTimestampLowerBound": 0,
  "attachmentTimestampUpperBound": 0,
  "nonce": ""
 }
]
```
