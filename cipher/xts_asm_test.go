//go:build (amd64 || arm64) && !purego

package cipher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

var testTweakVector = []string{
	"F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
	"66e94bd4ef8a2c3b884cfa59ca342b2e",
	"3f803bcd0d7fd2b37558419f59d5cda6",
	"6dcfba212f5d82bf525ee9793cfa505a",
	"c172964cd58be2b8d8e09d9c5e9cfe36",
	"1a267577a90caad6ae988e22714a2b8b",
	"33fab707493702e77ff8d66ba9e6c6fe",
	"23fb188b0f87f6ee2ec0803a99771341",
	"e8de0a4188b7efbc1ac3979eb906cf36",
}

func testDoubleTweak(t *testing.T, isGB bool) {
	for _, tk := range testTweakVector {
		tweak, _ := hex.DecodeString(tk)

		var t1, t2 [16]byte
		copy(t1[:], tweak)
		copy(t2[:], tweak)
		mul2(&t1, isGB)
		mul2Generic(&t2, isGB)

		if !bytes.Equal(t1[:], t2[:]) {
			t.Errorf("tweak %v, expected %x, got %x", tk, t2[:], t1[:])
		}
	}
}

func TestDoubleTweak(t *testing.T) {
	testDoubleTweak(t, false)
}

func TestDoubleTweakGB(t *testing.T) {
	testDoubleTweak(t, true)
}

func testDoubleTweakRandomly(t *testing.T, isGB bool) {
	var tweak, t1, t2 [16]byte
	io.ReadFull(rand.Reader, tweak[:])
	copy(t1[:], tweak[:])
	copy(t2[:], tweak[:])
	mul2(&t1, isGB)
	mul2Generic(&t2, isGB)

	if !bytes.Equal(t1[:], t2[:]) {
		t.Errorf("tweak %x, expected %x, got %x", tweak[:], t2[:], t1[:])
	}
}

func TestDoubleTweakRandomly(t *testing.T) {
	for i := 0; i < 10; i++ {
		testDoubleTweakRandomly(t, false)
	}
}

func TestDoubleTweakGBRandomly(t *testing.T) {
	for i := 0; i < 10; i++ {
		testDoubleTweakRandomly(t, true)
	}
}

func testDoubleTweaks(t *testing.T, isGB bool) {
	for _, tk := range testTweakVector {
		tweak, _ := hex.DecodeString(tk)

		var t1, t2 [16]byte
		var t11, t12 [128]byte
		copy(t1[:], tweak)
		copy(t2[:], tweak)

		for i := 0; i < 8; i++ {
			copy(t12[16*i:], t2[:])
			mul2Generic(&t2, isGB)
		}

		doubleTweaks(&t1, t11[:], isGB)

		if !bytes.Equal(t1[:], t2[:]) {
			t.Errorf("1 tweak %v, expected %x, got %x", tk, t2[:], t1[:])
		}
		if !bytes.Equal(t11[:], t12[:]) {
			t.Errorf("2 tweak %v, expected %x, got %x", tk, t12[:], t11[:])
		}
	}
}

func TestDoubleTweaks(t *testing.T) {
	testDoubleTweaks(t, false)
}

func TestDoubleTweaksGB(t *testing.T) {
	testDoubleTweaks(t, true)
}
