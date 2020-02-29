package slip10

import (
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wollac/iota-bip39-demo/bip32path"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSecp256k1(t *testing.T) {
	curve := Secp256k1()
	seed := mustDecodeHex("000102030405060708090a0b0c0d0e0f")

	var tests = []struct {
		path      string
		chainCode []byte
		private   []byte
		public    []byte
	}{
		{
			"m",
			mustDecodeHex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
			mustDecodeHex("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"),
			mustDecodeHex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"),
		},
		{
			"m/0H",
			mustDecodeHex("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
			mustDecodeHex("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
			mustDecodeHex("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
		},
		{
			"m/0H/1",
			mustDecodeHex("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"),
			mustDecodeHex("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
			mustDecodeHex("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
		},
		{
			"m/0H/1/2H",
			mustDecodeHex("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"),
			mustDecodeHex("cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"),
			mustDecodeHex("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"),
		},
		{
			"m/0H/1/2H/2",
			mustDecodeHex("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"),
			mustDecodeHex("0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"),
			mustDecodeHex("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"),
		},
		{
			"m/0H/1/2H/2/1000000000",
			mustDecodeHex("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"),
			mustDecodeHex("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"),
			mustDecodeHex("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"),
		},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.path, "/", "|"), func(t *testing.T) {
			path, err := bip32path.ParsePath(tt.path)
			require.NoError(t, err)
			key, err := DeriveKeyFromPath(seed, curve, path)
			require.NoError(t, err)

			assert.Equal(t, tt.chainCode, key.ChainCode, "unexpected chain code")
			assert.Equal(t, tt.private, key.Key, "unexpected private key")
			assert.Equal(t, tt.public, curve.PublicKey(key), "unexpected public key")
		})
	}
}

func TestNist256p1(t *testing.T) {
	curve := Nist256p1()
	seed := mustDecodeHex("000102030405060708090a0b0c0d0e0f")

	var tests = []struct {
		path      string
		chainCode []byte
		private   []byte
		public    []byte
	}{
		{
			"m",
			mustDecodeHex("beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"),
			mustDecodeHex("612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2"),
			mustDecodeHex("0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8"),
		},
		{
			"m/0H",
			mustDecodeHex("3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11"),
			mustDecodeHex("6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c"),
			mustDecodeHex("0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c"),
		},
		{
			"m/0H/1",
			mustDecodeHex("4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c"),
			mustDecodeHex("284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129"),
			mustDecodeHex("03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844"),
		},
		{
			"m/0H/1/2H",
			mustDecodeHex("98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318"),
			mustDecodeHex("694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7"),
			mustDecodeHex("0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0"),
		},
		{
			"m/0H/1/2H/2",
			mustDecodeHex("ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0"),
			mustDecodeHex("5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa"),
			mustDecodeHex("029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20"),
		},
		{
			"m/0H/1/2H/2/1000000000",
			mustDecodeHex("b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059"),
			mustDecodeHex("21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119"),
			mustDecodeHex("02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4"),
		},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.path, "/", "|"), func(t *testing.T) {
			path, err := bip32path.ParsePath(tt.path)
			require.NoError(t, err)
			key, err := DeriveKeyFromPath(seed, curve, path)
			require.NoError(t, err)

			assert.Equal(t, tt.chainCode, key.ChainCode, "unexpected chain code")
			assert.Equal(t, tt.private, key.Key, "unexpected private key")
			assert.Equal(t, tt.public, curve.PublicKey(key), "unexpected public key")
		})
	}
}

func TestEd25519(t *testing.T) {
	curve := Ed25519()
	seed := mustDecodeHex("000102030405060708090a0b0c0d0e0f")

	var tests = []struct {
		path      string
		chainCode []byte
		private   []byte
		public    []byte
	}{
		{
			"m",
			mustDecodeHex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
			mustDecodeHex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"),
			mustDecodeHex("00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
		},
		{
			"m/0H",
			mustDecodeHex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
			mustDecodeHex("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"),
			mustDecodeHex("008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
		},
		{
			"m/0H/1H",
			mustDecodeHex("a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"),
			mustDecodeHex("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"),
			mustDecodeHex("001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
		},
		{
			"m/0H/1H/2H",
			mustDecodeHex("2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"),
			mustDecodeHex("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"),
			mustDecodeHex("00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1"),
		},
		{
			"m/0H/1H/2H/2H",
			mustDecodeHex("8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"),
			mustDecodeHex("30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"),
			mustDecodeHex("008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c"),
		},
		{
			"m/0H/1H/2H/2H/1000000000H",
			mustDecodeHex("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"),
			mustDecodeHex("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"),
			mustDecodeHex("003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a"),
		},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.path, "/", "|"), func(t *testing.T) {
			path, err := bip32path.ParsePath(tt.path)
			require.NoError(t, err)
			key, err := DeriveKeyFromPath(seed, curve, path)
			require.NoError(t, err)

			assert.Equal(t, tt.chainCode, key.ChainCode, "unexpected chain code")
			assert.Equal(t, tt.private, key.Key, "unexpected private key")
			assert.Equal(t, tt.public, curve.PublicKey(key), "unexpected public key")
		})
	}
}

func BenchmarkDeriveKeyFromPath(b *testing.B) {
	seed := mustDecodeHex("000102030405060708090a0b0c0d0e0f")
	var path []uint32
	for i := 0; i < b.N; i++ {
		path = append(path, rand.Uint32())
	}
	b.ResetTimer()

	_, _ = DeriveKeyFromPath(seed, Nist256p1(), path)
}
