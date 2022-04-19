package rc5

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html#rfc.section.4
func Test_RC5_642424(t *testing.T) {
	testData := &Crypt32Test{
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"000102030405060708090A0B0C0D0E0F",
		"A46772820EDBCE0235ABEA32AE7178DA",
	}
	key, _ := hex.DecodeString(testData.key)
	in, _ := hex.DecodeString(testData.in)
	target, _ := hex.DecodeString(testData.out)
	out := make([]byte, 16)
	dst := make([]byte, 16)
	c, err := NewCipher64(key, 24)
	if err != nil {
		t.Error(err)
	}
	c.Encrypt(out, in)
	if !reflect.DeepEqual(out, target) {
		t.Errorf("expected=%v, result=%v\n", testData.out, strings.ToUpper(hex.EncodeToString(out)))
	}
	c.Decrypt(dst, out)
	if !reflect.DeepEqual(dst, in) {
		t.Errorf("expected=%v, result=%v\n", testData.in, strings.ToUpper(hex.EncodeToString(dst)))
	}
}
