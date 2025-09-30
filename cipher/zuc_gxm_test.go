// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package cipher_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/zuc"
)

// GM/T 0001.4 - 2024 Appendix C.2
var gxmTestCases = []struct {
	iv      string
	h       string
	k       string
	a       string
	p       string
	result  string
	tagSize int
}{
	{
		iv:      "b3a6db3c870c3e99245e0d1c06b747de",
		h:       "6db45e4f9572f4e6fe0d91acda6801d5",
		k:       "edbe06afed8075576aad04afdec91d32",
		a:       "9de18b1fdab0ca9902b9729d492c807ec599d5",
		p:       "",
		result:  "2a14afaeb6e5ecc784fad24ddeb457d2",
		tagSize: 16,
	},
	{
		iv:      "2923be84e16cd6ae529049f1f1bbe9eb",
		h:       "27bede74018082da87d4e5b69f18bf66",
		k:       "32070e0f39b7b692b4673edc3184a48e",
		a:       "",
		p:       "",
		result:  "5d8a045ac89a681a4bc910380bbadccf",
		tagSize: 16,
	},
	{
		iv:      "2d2086832cc2fe3fd18cb51d6c5e99a5",
		h:       "9d6cb51623fd847f2e45d7f52f900db8",
		k:       "56131c03e457f6226b5477633b873984",
		a:       "",
		p:       "ffffffffffffffffffffffffffffff",
		result:  "b78e2f30cf70252d58767997f1b086efb30febbfe0c88a1e77b1dde9d45525",
		tagSize: 16,
	},
	{
		iv:      "bb8b76cfe5f0d9335029008b2a3b2b21",
		h:       "ee767d503bb3d5d1b585f57a0418c673",
		k:       "e4b5c1f8578034ce6424f58c675597ac",
		a:       "fcdd4cb97995da30efd957194eac4d2a8610470f99c88657f462f68dff7561a5",
		p:       "5fee5517627f17b22a96caf97b77ec7f667cc47d13c34923be2441300066a6c150b24d66c947ca7b2e708eb62bb352",
		result:  "b56da5c99238b04a45e3d9d96f12f3dc052e428fa5a5817292ee23dbdad9782cf66f55c846e55dc68f47eaf8378e7051c7aedd9e1c7d74c38059f5e7e3a742",
		tagSize: 16,
	},
	{
		iv:      "3615df810cc677f15080faa1dd44aad3",
		h:       "fdfaddc476785c25906fe42ba63a93b7",
		k:       "f405d652b6362e70f8362bd383b7298b",
		a:       "5fee5517627f17b22a96caf97b77ec7f667cc47d13c34923be2441300066a6c150b24d66c947ca7b2e708eb62bb352fc",
		p:       "dd4cb97995da30efd957194eac4d2a8610470f99c88657f462f68dff7561a5f3",
		result:  "1134ffc119ad163e914989474be6c072fd5867f3989d8b15899ebd10a4a248c98829aaa4f9891822",
		tagSize: 8,
	},
}

func TestGXMSeal(t *testing.T) {
	for i, tc := range gxmTestCases {
		key, _ := hex.DecodeString(tc.k)
		iv, _ := hex.DecodeString(tc.iv)
		h, _ := hex.DecodeString(tc.h)
		a, _ := hex.DecodeString(tc.a)
		p, _ := hex.DecodeString(tc.p)
		expected, _ := hex.DecodeString(tc.result)

		eea, err := zuc.NewCipher(key, iv)
		if err != nil {
			t.Fatalf("case %d: NewCipher error: %s", i, err)
		}
		c, err := cipher.NewGXMWithTagSize(eea, h, tc.tagSize)
		if err != nil {
			t.Fatalf("case %d: NewGXM error: %s", i, err)
		}
		out := c.Seal(nil, p, a)
		if !bytes.Equal(out, expected) {
			t.Errorf("case %d: incorrect ciphertext\n got:  %x\nwant: %x", i, out, expected)
		}
	}
}

func TestGXMOpen(t *testing.T) {
	for i, tc := range gxmTestCases {
		key, _ := hex.DecodeString(tc.k)
		iv, _ := hex.DecodeString(tc.iv)
		h, _ := hex.DecodeString(tc.h)
		a, _ := hex.DecodeString(tc.a)
		p, _ := hex.DecodeString(tc.p)
		expected, _ := hex.DecodeString(tc.result)

		eea, err := zuc.NewCipher(key, iv)
		if err != nil {
			t.Fatalf("case %d: NewCipher error: %s", i, err)
		}
		c, err := cipher.NewGXMWithTagSize(eea, h, tc.tagSize)
		if err != nil {
			t.Fatalf("case %d: NewGXM error: %s", i, err)
		}
		out, err := c.Open(nil, expected, a)
		if err != nil {
			t.Fatalf("case %d: Open error: %s", i, err)
		}
		if !bytes.Equal(out, p) {
			t.Errorf("case %d: incorrect plaintext\n got:  %x\nwant: %x", i, out, p)
		}
	}
}
