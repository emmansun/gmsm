//go:build !(arm || mips)

package cipher_test

import (
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/cipher"
)

func TestCCMLongAd(t *testing.T) {
	key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
	nonce, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1db")

	c, _ := aes.NewCipher(key)
	aesccm, _ := cipher.NewCCM(c)

	ad := make([]byte, 0x10000)
	ct := aesccm.Seal(nil, nonce, nil, ad)
	if hex.EncodeToString(ct) != "e1ad65c3bfaba94b1085aff8c6ea2698" {
		t.Errorf("got %s, want e1ad65c3bfaba94b1085aff8c6ea2698", hex.EncodeToString(ct))
	}

	ad = make([]byte, 1<<32+1)
	ct = aesccm.Seal(nil, nonce, nil, ad)
	if hex.EncodeToString(ct) != "c1949a661c605ff5640a29dd3e285ddb" {
		t.Errorf("got %s, want c1949a661c605ff5640a29dd3e285ddb", hex.EncodeToString(ct))
	}
}
