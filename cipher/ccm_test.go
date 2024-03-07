package cipher_test

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/cipher"
)

// https://tools.ietf.org/html/rfc3610, 8. Test Vectors
var aesCCMTests = []struct {
	key, nonce, plaintext, ad, result string
	tagSize                           int
}{
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000003020100a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"0001020304050607",
		"588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000004030201a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0001020304050607",
		"72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000005040302a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"0001020304050607",
		"51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000006050403a0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e",
		"000102030405060708090a0b",
		"a28c6865939a9a79faaa5c4c2a9d4a91cdac8c96c861b9c9e61ef1",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000007060504a0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000102030405060708090a0b",
		"dcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e51e83f077d9c2d93",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000008070605a0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"000102030405060708090a0b",
		"6fc1b011f006568b5171a42d953d469b2570a4bd87405a0443ac91cb94",
		8,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"00000009080706a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"0001020304050607",
		"0135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490",
		10,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"0000000a090807a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"0001020304050607",
		"7b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4",
		10,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"0000000b0a0908a0a1a2a3a4a5",
		"08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"0001020304050607",
		"82531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197ea9c07e56b5eb17e5f4e",
		10,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"0000000c0b0a09a0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e",
		"000102030405060708090a0b",
		"07342594157785152b074098330abb141b947b566aa9406b4d999988dd",
		10,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"0000000d0c0b0aa0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"000102030405060708090a0b",
		"676bb20380b0e301e8ab79590a396da78b834934f53aa2e9107a8b6c022c",
		10,
	},
	{
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
		"0000000e0d0c0ba0a1a2a3a4a5",
		"0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"000102030405060708090a0b",
		"c0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43cd1aa31662e7ad65d6db",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"00412b4ea9cdbe3c9696766cfa",
		"08e8cf97d820ea258460e96ad9cf5289054d895ceac47c",
		"0be1a88bace018b1",
		"4cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3",
		8,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"0033568ef7b2633c9696766cfa",
		"9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec",
		"63018f76dc8a1bcb",
		"4ccb1e7ca981befaa0726c55d378061298c85c92814abc33c52ee81d7d77c08a",
		8,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"00f8b678094e3b3c9696766cfa",
		"e88b6a46c78d63e52eb8c546efb5de6f75e9cc0d",
		"77b60f011c03e1525899bcae",
		"5545ff1a085ee2efbf52b2e04bee1e2336c73e3f762c0c7744fe7e3c",
		8,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"00d560912d3f703c9696766cfa",
		"6435acbafb11a82e2f071d7ca4a5ebd93a803ba87f",
		"cd9044d2b71fdb8120ea60c0",
		"009769ecabdf48625594c59251e6035722675e04c847099e5ae0704551",
		8,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"0042fff8f1951c3c9696766cfa",
		"8a19b950bcf71a018e5e6701c91787659809d67dbedd18",
		"d85bc7e69f944fb8",
		"bc218daa947427b6db386a99ac1aef23ade0b52939cb6a637cf9bec2408897c6ba",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"00920f40e56cdc3c9696766cfa",
		"1761433c37c5a35fc1f39f406302eb907c6163be38c98437",
		"74a0ebc9069f5b37",
		"5810e6fd25874022e80361a478e3e9cf484ab04f447efff6f0a477cc2fc9bf548944",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"0027ca0c7120bc3c9696766cfa",
		"a434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa",
		"44a3aa3aae6475ca",
		"f2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f1544d4151a4ed3a8b87b9ce",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"005b8ccbcd9af83c9696766cfa",
		"b96b49e21d621741632875db7f6c9243d2d7c2",
		"ec46bb63b02520c33c49fd70",
		"31d750a09da3ed7fddd49a2032aabf17ec8ebf7d22c8088c666be5c197",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"003ebe94044b9a3c9696766cfa",
		"e2fcfbb880442c731bf95167c8ffd7895e337076",
		"47a65ac78b3d594227e85e71",
		"e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d",
		10,
	},
	{
		"d7828d13b2b0bdc325a76236df93cc6b",
		"008d493b30ae8b3c9696766cfa",
		"abf21c0b02feb88f856df4a37381bce3cc128517d4",
		"6e37a6ef546d955d34ab6059",
		"f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059",
		10,
	},
}

func TestCCMWithAES(t *testing.T) {
	for i, tt := range aesCCMTests {
		nonce, _ := hex.DecodeString(tt.nonce)
		plaintext, _ := hex.DecodeString(tt.plaintext)
		ad, _ := hex.DecodeString(tt.ad)
		key, _ := hex.DecodeString(tt.key)
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		aesccm, err := cipher.NewCCMWithNonceAndTagSize(c, len(nonce), tt.tagSize)
		if err != nil {
			t.Fatal(err)
		}
		ct := aesccm.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != tt.result {
			t.Errorf("#%d: got %s, want %s", i, ctHex, tt.result)
			continue
		}

		//func (c *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error)
		pt, err := aesccm.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Fatal(err)
		}
		if ptHex := hex.EncodeToString(pt); ptHex != tt.plaintext {
			t.Errorf("#%d: got %s, want %s", i, ptHex, tt.plaintext)
			continue
		}
	}
}

func TestCCMInvalidTagSize(t *testing.T) {
	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")

	c, _ := aes.NewCipher(key)

	for _, tagSize := range []int{0, 1, c.BlockSize() + 1} {
		aesccm, err := cipher.NewCCMWithTagSize(c, tagSize)
		if aesccm != nil || err == nil {
			t.Fatalf("NewCCMWithNonceAndTagSize was successful with an invalid %d-byte tag size", tagSize)
		}
	}
}

func TestCCMInvalidNonceSize(t *testing.T) {
	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")

	c, _ := aes.NewCipher(key)

	for _, nonceSize := range []int{0, 1, c.BlockSize() + 1} {
		aesccm, err := cipher.NewCCMWithNonceSize(c, nonceSize)
		if aesccm != nil || err == nil {
			t.Fatalf("NewCCMWithNonceSize was successful with an invalid %d-byte tag size", nonceSize)
		}
	}
}

func TestCCMTagFailureOverwrite(t *testing.T) {
	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
	nonce, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1db")
	ciphertext, _ := hex.DecodeString("0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c")

	c, _ := aes.NewCipher(key)
	aesccm, _ := cipher.NewCCM(c)

	dst := make([]byte, len(ciphertext)-16)
	for i := range dst {
		dst[i] = 42
	}

	result, err := aesccm.Open(dst[:0], nonce, ciphertext, nil)
	if err == nil {
		t.Fatal("Bad Open still resulted in nil error.")
	}

	if result != nil {
		t.Fatal("Failed Open returned non-nil result.")
	}

	for i := range dst {
		if dst[i] != 0 {
			t.Fatal("Failed Open didn't zero dst buffer")
		}
	}
}
