// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm3

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/emmansun/gmsm/internal/byteorder"
)

// katHashVectors contains known-answer test vectors from GB/T 32905-2016.
var katHashVectors = []struct {
	in  []byte
	out string
}{
	{
		[]byte("abc"),
		"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	},
	{
		[]byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"),
		"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
	},
}

// KATHash verifies SM3 hash with GB/T 32905-2016 standard vectors.
func KATHash() error {
	for i, tv := range katHashVectors {
		h := New()
		h.Write(tv.in)
		got := h.Sum(nil)
		want, _ := hex.DecodeString(tv.out)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return errors.New("hash mismatch for vector " + string(rune('0'+i)))
		}
	}
	return nil
}

// KATBlock verifies SM3 compression function with a known block vector.
func KATBlock() error {
	// "abc" padded block: 0x61626380 followed by 56 zero bytes and length 0x18
	var data [64]byte
	data[0] = 'a'
	data[1] = 'b'
	data[2] = 'c'
	data[3] = 0x80
	data[63] = 0x18

	d := New().(*digest)
	block(d, data[:])

	var got [Size]byte
	byteorder.BEPutUint32(got[0:], d.h[0])
	byteorder.BEPutUint32(got[4:], d.h[1])
	byteorder.BEPutUint32(got[8:], d.h[2])
	byteorder.BEPutUint32(got[12:], d.h[3])
	byteorder.BEPutUint32(got[16:], d.h[4])
	byteorder.BEPutUint32(got[20:], d.h[5])
	byteorder.BEPutUint32(got[24:], d.h[6])
	byteorder.BEPutUint32(got[28:], d.h[7])

	want, _ := hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return errors.New("block function output mismatch")
	}
	return nil
}

// KATIncremental verifies that incremental writes produce the same result as a single write.
func KATIncremental() error {
	msg := []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	h1 := New()
	h1.Write(msg[:len(msg)/2])
	h1.Write(msg[len(msg)/2:])
	got1 := h1.Sum(nil)

	h2 := New()
	h2.Write(msg)
	got2 := h2.Sum(nil)

	if subtle.ConstantTimeCompare(got1, got2) != 1 {
		return errors.New("incremental write consistency check failed")
	}
	return nil
}
