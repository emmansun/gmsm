// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/emmansun/gmsm/internal/sm3"
)

func TestEncryptRetry(t *testing.T) {
	c := P256()
	privateScalar := make([]byte, c.N.Size())
	privateScalar[len(privateScalar)-1] = 1
	publicPoint, err := c.newPoint().ScalarBaseMult(privateScalar)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := NewPrivateKey(privateScalar, publicPoint.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var zeroScalar, nonzeroScalar []byte
	for candidate := 2; candidate < 4096; candidate++ {
		scalar := make([]byte, c.N.Size())
		scalar[len(scalar)-2] = byte(candidate >> 8)
		scalar[len(scalar)-1] = byte(candidate)
		point, err := c.newPoint().ScalarBaseMult(scalar)
		if err != nil {
			t.Fatal(err)
		}
		if sm3.Kdf(point.Bytes()[1:], 1)[0] == 0 {
			zeroScalar = scalar
		} else {
			nonzeroScalar = scalar
		}
		if zeroScalar != nil && nonzeroScalar != nil {
			break
		}
	}
	if zeroScalar == nil || nonzeroScalar == nil {
		t.Fatal("could not find scalars for the KDF retry test")
	}
	random := bytes.NewReader(append(zeroScalar, nonzeroScalar...))
	msg := []byte{0x42}
	ciphertext, err := Encrypt(random, &priv.pub, msg)
	if err != nil {
		t.Fatal(err)
	}
	if random.Len() != 0 {
		t.Fatal("encryption did not consume both scalars")
	}
	plaintext, err := Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, msg) {
		t.Fatalf("plaintext = %x, want %x", plaintext, msg)
	}
}

func TestRandomPoint(t *testing.T) {
	c := P256()
	t.Cleanup(func() { testingOnlyRejectionSamplingLooped = nil })
	var loopCount int
	testingOnlyRejectionSamplingLooped = func() { loopCount++ }

	// A sequence of all ones will generate 2^N-1, which should be rejected.
	// (Unless, for example, we are masking too many bits.)
	r := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0xff}, 100)), rand.Reader)
	randfunc := func(b []byte) error {
		_, err := io.ReadFull(r, b)
		return err
	}
	if k, p, err := randomPoint(c, randfunc, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("overflow was not rejected")
	}
	loopCount = 0

	// A sequence of all zeroes will generate zero, which should be rejected.
	r = io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{0}, 100)), rand.Reader)
	randfunc = func(b []byte) error {
		_, err := io.ReadFull(r, b)
		return err
	}
	if k, p, err := randomPoint(c, randfunc, false); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("zero was not rejected")
	}
}
