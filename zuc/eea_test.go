package zuc

import (
	"encoding/hex"
	"testing"
)

var zucEEATests = []struct {
	key       string
	count     uint32
	bearer    uint32
	direction uint32
	in        string
	out       string
}{
	{
		"173d14ba5003731d7a60049470f00a29",
		0x66035492,
		0xf,
		0,
		"6cf65340735552ab0c9752fa6f9025fe0bd675d9005875b2",
		"a6c85fc66afb8533aafc2518dfe784940ee1e4b030238cc8",
	},
	{
		"e5bd3ea0eb55ade866c6ac58bd54302a",
		0x56823,
		0x18,
		1,
		"14a8ef693d678507bbe7270a7f67ff5006c3525b9807e467c4e56000ba338f5d429559036751822246c80d3b38f07f4be2d8ff5805f5132229bde93bbbdcaf382bf1ee972fbf9977bada8945847a2a6c9ad34a667554e04d1f7fa2c33241bd8f01ba220d",
		"131d43e0dea1be5c5a1bfd971d852cbf712d7b4f57961fea3208afa8bca433f456ad09c7417e58bc69cf8866d1353f74865e80781d202dfb3ecff7fcbc3b190fe82a204ed0e350fc0f6f2613b2f2bca6df5a473a57a4a00d985ebad880d6f23864a07b01",
	},
}

func Test_EEA(t *testing.T) {
	for i, test := range zucEEATests {
		key, err := hex.DecodeString(test.key)
		if err != nil {
			t.Error(err)
		}
		c, err := NewEEACipher(key, test.count, test.bearer, test.direction)
		if err != nil {
			t.Error(err)
		}
		in, err := hex.DecodeString(test.in)
		out := make([]byte, len(in))
		if err != nil {
			t.Error(err)
		}
		c.XORKeyStream(out, in)
		if hex.EncodeToString(out) != test.out {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.out, hex.EncodeToString(out))
		}
	}
}
