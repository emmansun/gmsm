package cipher_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
)

var hctrSM4TestVectors = []struct {
	key        string
	hashKey    string
	tweak      string
	plaintext  string
	ciphertext string
}{
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c37106bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c37106bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		"8858dda3034233e377936b76ce7edeb6a245075a37800b0b996e8e974c9032ac8de40d90ee4ee5fb58bc10cbc95779485ab38ffb0b4f961d85f086db705ff723edbeaec649b3b406b11b96a418a9c2c51ef41cdd24e472c18336e9efcd07b7e264a1e2d46615198eb74938d72104fa89294a6360cdb6b032a704cf07a087bb2283598552701b2f710d6528d9c3f4dab529afef4413f25169b6cbf8168ccbfa02a2f507513d0cb3802da34dbd928b67e6afc30ca91011070cfd40c2ef3d4ac041",
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
		"9cd7481d3b7ca904b14b4084d9d4c83ed39eac8e16747895fc2ae1eecd220276af3d0d2f21cb3807561347c81ad138117dd85c652afe16a47dc68eb884068ae3",
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b",
		"f7505aff357ac13107cdb2848c6bb2dcdda473f7a6ea939d44f52c986c11ca9341042f2b0091a1ca5c8f708cae8ca6a5c59e2228b3616c4455627722",
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"000102030405060708090A0B0C0D0E0F",
		"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
		"6bc1bee22e409f96e93d7e117393172a",
		"b7b1dd75f608012dc69621d4ea720a60",
	},
}

func TestHCTR(t *testing.T) {
	for i, test := range hctrSM4TestVectors {
		key1, _ := hex.DecodeString(test.key)
		key2, _ := hex.DecodeString(test.hashKey)
		tw, _ := hex.DecodeString(test.tweak)
		plaintext, _ := hex.DecodeString(test.plaintext)
		ciphertext, _ := hex.DecodeString(test.ciphertext)
		got := make([]byte, len(plaintext))
		c, err := sm4.NewCipher(key1)
		if err != nil {
			t.Fatal(err)
		}
		hctr, err := cipher.NewHCTR(c, tw, key2)
		if err != nil {
			t.Fatal(err)
		}
		hctr.Encrypt(got, plaintext)
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("%v case encrypt failed, got %x\n", i+1, got)
		}

		hctr.Decrypt(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%v case decrypt failed, got %x\n", i+1, got)
		}
	}
}
