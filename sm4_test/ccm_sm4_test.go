package sm4_test

import (
	"encoding/hex"
	"testing"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
)

var sm4CCMTests = []struct {
	key, nonce, plaintext, ad, result string
}{
	{ // https://tools.ietf.org/html/rfc8998 A.2. SM4-CCM Test Vectors
		"0123456789abcdeffedcba9876543210",
		"00001234567800000000abcd",
		"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
		"feedfacedeadbeeffeedfacedeadbeefabaddad2",
		"48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b16842d4fa186f56ab33256971fa110f4",
	},
}

func TestCCM(t *testing.T) {
	for i, tt := range sm4CCMTests {
		nonce, _ := hex.DecodeString(tt.nonce)
		plaintext, _ := hex.DecodeString(tt.plaintext)
		ad, _ := hex.DecodeString(tt.ad)
		key, _ := hex.DecodeString(tt.key)
		tagSize := (len(tt.result) - len(tt.plaintext)) / 2
		c, err := sm4.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		sm4ccm, err := smcipher.NewCCMWithNonceAndTagSize(c, len(nonce), tagSize)
		if err != nil {
			t.Fatal(err)
		}
		ct := sm4ccm.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != tt.result {
			t.Errorf("#%d: got %s, want %s", i, ctHex, tt.result)
			continue
		}

		//func (c *ccm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error)
		pt, err := sm4ccm.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Fatal(err)
		}
		if ptHex := hex.EncodeToString(pt); ptHex != tt.plaintext {
			t.Errorf("#%d: got %s, want %s", i, ptHex, tt.plaintext)
			continue
		}
	}
}
