package rc5

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

type Crypt32Test struct {
	key string
	in  string
	out string
}

// http://people.csail.mit.edu/rivest/Rivest-rc5rev.pdf
// RC5-32/12/16
var encrypt32Tests = []Crypt32Test{
	{
		"00000000000000000000000000000000",
		"0000000000000000",
		"21A5DBEE154B8F6D",
	},
	{
		"915F4619BE41B2516355A50110A9CE91",
		"21A5DBEE154B8F6D",
		"F7C013AC5B2B8952",
	},
	{
		"783348E75AEB0F2FD7B169BB8DC16787",
		"F7C013AC5B2B8952",
		"2F42B3B70369FC92",
	},
	{
		"DC49DB1375A5584F6485B413B5F12BAF",
		"2F42B3B70369FC92",
		"65C178B284D197CC",
	},
	{
		"5269F149D41BA0152497574D7F153125",
		"65C178B284D197CC",
		"EB44E415DA319824",
	},
}

func Test_rc5Cipher32_Encrypt(t *testing.T) {
	for _, test := range encrypt32Tests {
		key, _ := hex.DecodeString(test.key)
		in, _ := hex.DecodeString(test.in)
		target, _ := hex.DecodeString(test.out)
		out := make([]byte, 8)
		dst := make([]byte, 8)
		c, err := NewCipher32(key, 12)
		if err != nil {
			t.Error(err)
		}

		c.Encrypt(out, in)
		if !reflect.DeepEqual(out, target) {
			t.Errorf("expected=%v, result=%v\n", test.out, strings.ToUpper(hex.EncodeToString(out)))
		}
		c.Decrypt(dst, out)
		if !reflect.DeepEqual(dst, in) {
			t.Errorf("expected=%v, result=%v\n", test.in, strings.ToUpper(hex.EncodeToString(dst)))
		}
	}
}

// https://tools.ietf.org/id/draft-krovetz-rc6-rc5-vectors-00.html#rfc.section.4
func Test_RC5_322016(t *testing.T) {
	testData := &Crypt32Test{
		"000102030405060708090A0B0C0D0E0F",
		"0001020304050607",
		"2A0EDC0E9431FF73",
	}
	key, _ := hex.DecodeString(testData.key)
	in, _ := hex.DecodeString(testData.in)
	target, _ := hex.DecodeString(testData.out)
	out := make([]byte, 8)
	dst := make([]byte, 8)
	c, err := NewCipher32(key, 20)
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
