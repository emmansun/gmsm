package cipher_test

import (
	"bytes"
	_cipher "crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/zuc"
)

var murTestCases = []struct {
	iv      string
	h       string
	k1      string
	k2      string
	a       string
	p       string
	result  string
	tagSize int
}{
	// GM/T 0001.4 - 2024 Appendix C.3
	{
		iv:      "bb8b76cfe5f0d9335029008b2a3b2b21",
		h:       "ee767d503bb3d5d1b585f57a0418c673",
		k1:      "e4b5c1f8578034ce6424f58c675597ac",
		k2:      "608053f6af9efda562d95dc013bea6b5",
		a:       "fcdd4cb97995da30efd957194eac4d2a8610470f99c88657f462f68dff7561a5",
		p:       "5fee5517627f17b22a96caf97b77ec7f667cc47d13c34923be2441300066a6c150b24d66c947ca7b2e708eb62bb352",
		result:  "cf5594bd30c0da0fb41fa6054e534d0494c9d6c4f132fc85771a473458b09583b825c662bfd82278178a845e281e5415c5d1a78a42c4dcd67db05fa1a640a0",
		tagSize: 16,
	},
	{
		iv:      "2923be84e16cd6ae529049f1f1bbe9eb",
		h:       "27bede74018082da87d4e5b69f18bf66",
		k1:      "32070e0f39b7b692b4673edc3184a48e",
		k2:      "27636f4414510d62cc15cfe194ec4f6d",
		a:       "",
		p:       "",
		result:  "c0016e0772c9983d0fd9fd8c1b012845",
		tagSize: 16,
	},
	{
		iv:      "2d2086832cc2fe3fd18cb51d6c5e99a5",
		h:       "9d6cb51623fd847f2e45d7f52f900db8",
		k1:      "56131c03e457f6226b5477633b873984",
		k2:      "a88981534db331a386de3e52fb46029b",
		a:       "",
		p:       "ffffffffffffffffffffffffffffff",
		result:  "234c2d51eaa582da9be3cc3828aa670a7afb7d817efa0777826f1e33a53cf3",
		tagSize: 16,
	},
	{
		iv:      "b3a6db3c870c3e99245e0d1c06b747de",
		h:       "6db45e4f9572f4e6fe0d91acda6801d5",
		k1:      "edbe06afed8075576aad04afdec91d32",
		k2:      "61d4fca6b2c2bb48b4b1172531333620",
		a:       "9de18b1fdab0ca9902b9729d492c807ec599d5",
		p:       "",
		result:  "8213c29606d02bba10f13ffad1d26a42",
		tagSize: 16,
	},
	{
		iv:      "b3a6db3c870c3e99245e0d1c06b747de",
		h:       "6db45e4f9572f4e6fe0d91acda6801d5",
		k1:      "edbe06afed8075576aad04afdec91d32",
		k2:      "61d4fca6b2c2bb48b4b1172531333620",
		a:       "9de18b1fdab0ca9902b9729d492c807ec599d5e980b2eac9cc53bf67d6bf14d67e2ddc8e6683ef574961ff698f61cdd1",
		p:       "b3124dc843bb8ba61f035a7d0938251f5dd4cbfc96f5453b130d890a1cdbae32",
		result:  "dabbbe23d8f0ea42e31a9bdd9706a4275d8aacd2cf27c4a4c0d0ba6fb8f31da7a276827b74509357",
		tagSize: 8,
	},
}

func TestMurSeal(t *testing.T) {
	zucCipherCreator := func(key, iv []byte) (_cipher.Stream, error) {
		return zuc.NewCipher(key, iv)
	}
	for i, tc := range murTestCases {
		iv, _ := hex.DecodeString(tc.iv)
		h, _ := hex.DecodeString(tc.h)
		k1, _ := hex.DecodeString(tc.k1)
		k2, _ := hex.DecodeString(tc.k2)
		a, _ := hex.DecodeString(tc.a)
		p, _ := hex.DecodeString(tc.p)
		result, _ := hex.DecodeString(tc.result)

		g, err := cipher.NewMURWithTagSize(zucCipherCreator, h, tc.tagSize)
		if err != nil {
			t.Errorf("case %d: NewMURWithTagSize error: %s", i, err)
			continue
		}
		c, err := g.Seal(iv, k1, k2, nil, p, a)
		if err != nil {
			t.Errorf("case %d: Seal error: %s", i, err)
			continue
		}
		if !bytes.Equal(c, result) {
			t.Errorf("case %d: Seal mismatch\ngot:  %x\nwant: %x", i, c, result)
			continue
		}
	}
}

func TestMurOpen(t *testing.T) {
	zucCipherCreator := func(key, iv []byte) (_cipher.Stream, error) {
		return zuc.NewCipher(key, iv)
	}
	for i, tc := range murTestCases {
		iv, _ := hex.DecodeString(tc.iv)
		h, _ := hex.DecodeString(tc.h)
		k1, _ := hex.DecodeString(tc.k1)
		k2, _ := hex.DecodeString(tc.k2)
		a, _ := hex.DecodeString(tc.a)
		p, _ := hex.DecodeString(tc.p)
		result, _ := hex.DecodeString(tc.result)

		g, err := cipher.NewMURWithTagSize(zucCipherCreator, h, tc.tagSize)
		if err != nil {
			t.Errorf("case %d: NewMURWithTagSize error: %s", i, err)
			continue
		}
		out, err := g.Open(iv, k1, k2, nil, result, a)
		if err != nil {
			t.Errorf("case %d: Open error: %s", i, err)
			continue
		}
		if !bytes.Equal(out, p) {
			t.Errorf("case %d: Open mismatch\ngot:  %x\nwant: %x", i, out, p)
			continue
		}
	}
}
