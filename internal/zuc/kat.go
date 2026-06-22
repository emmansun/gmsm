// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package zuc

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// katEEAVector holds a ZUC EEA known-answer test vector.
type katEEAVector struct {
	key       string
	count     uint32
	bearer    uint32
	direction uint32
	in        string
	out       string
}

// katEEAVectors from the ZUC specification.
var katEEAVectors = []katEEAVector{
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

// KATEEA verifies ZUC EEA (encryption) with standard known-answer vectors.
func KATEEA() error {
	for i, tv := range katEEAVectors {
		key, _ := hex.DecodeString(tv.key)
		in, _ := hex.DecodeString(tv.in)
		want, _ := hex.DecodeString(tv.out)

		c, err := NewEEACipher(key, tv.count, tv.bearer, tv.direction)
		if err != nil {
			return errors.New("EEA cipher creation failed for vector " + string(rune('0'+i)) + ": " + err.Error())
		}
		out := make([]byte, len(in))
		copy(out, in)
		c.XORKeyStream(out, out)
		if subtle.ConstantTimeCompare(out, want) != 1 {
			return errors.New("EEA output mismatch for vector " + string(rune('0'+i)))
		}
	}
	return nil
}

// katEIAVector holds a ZUC EIA known-answer test vector.
type katEIAVector struct {
	key       []byte
	count     uint32
	bearer    uint32
	direction uint32
	in        []byte
	nbits     int
	mac       string
}

// katEIAVectors from the ZUC specification.
var katEIAVectors = []katEIAVector{
	{
		key:       make([]byte, 16),
		count:     0,
		bearer:    0,
		direction: 0,
		in:        []byte{0x00, 0x00, 0x00, 0x00},
		nbits:     1,
		mac:       "c8a9595e",
	},
}

// KATEIA verifies ZUC EIA (integrity) with standard known-answer vectors.
func KATEIA() error {
	for i, tv := range katEIAVectors {
		h, err := NewEIAHash(tv.key, tv.count, tv.bearer, tv.direction)
		if err != nil {
			return errors.New("EIA hash creation failed for vector " + string(rune('0'+i)) + ": " + err.Error())
		}
		mac := h.Finish(tv.in, tv.nbits)
		want, _ := hex.DecodeString(tv.mac)
		if subtle.ConstantTimeCompare(mac, want) != 1 {
			return errors.New("EIA MAC mismatch for vector " + string(rune('0'+i)))
		}
	}
	return nil
}
