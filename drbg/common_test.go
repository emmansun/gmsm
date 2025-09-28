package drbg

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"testing"
)

func TestGmCtrDrbgPrng(t *testing.T) {
	prng, err := NewGmCtrDrbgPrng(nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 33)
	for i := 0; i < int(reseedCounterIntervalLevelTest+1); i++ {
		n, err := prng.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		if n != 33 {
			t.Errorf("not got enough random bytes")
		}
	}
}

func TestGmCtrDrbgPrngReseedCase(t *testing.T) {
	prng, err := NewGmCtrDrbgPrng(nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 64)
	for i := 0; i < int(reseedCounterIntervalLevelTest+1); i++ {
		for j := 0; j < 64; j++ {
			data[j] = 0
		}
		n, err := prng.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		if n != 64 {
			t.Errorf("not got enough random bytes")
		}
		if bytes.Contains(data, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
			t.Fatal("failed, it's a bug")
		}
	}
}

func TestNistCtrDrbgPrng(t *testing.T) {
	prng, err := NewNistCtrDrbgPrng(aes.NewCipher, 16, nil, 16, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxBytesPerGenerate+1)
	n, err := prng.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != maxBytesPerGenerate+1 {
		t.Errorf("not got enough random bytes")
	}
}

func TestGmHashDrbgPrng(t *testing.T) {
	prng, err := NewGmHashDrbgPrng(nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 33)
	for i := 0; i < int(reseedCounterIntervalLevelTest+1); i++ {
		n, err := prng.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		if n != 33 {
			t.Errorf("not got enough random bytes")
		}
	}
}

func TestNistHashDrbgPrng(t *testing.T) {
	prng, err := NewNistHashDrbgPrng(sha256.New, nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxBytesPerGenerate+1)
	n, err := prng.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != maxBytesPerGenerate+1 {
		t.Errorf("not got enough random bytes")
	}
}

func TestNistHmacDrbgPrng(t *testing.T) {
	prng, err := NewNistHmacDrbgPrng(sha256.New, nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, maxBytesPerGenerate+1)
	n, err := prng.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != maxBytesPerGenerate+1 {
		t.Errorf("not got enough random bytes")
	}
}

func TestGMSecurityStrengthValidation(t *testing.T) {
	_, err := NewGmHashDrbgPrng(nil, 24, SECURITY_LEVEL_TEST, nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
	_, err = NewGmCtrDrbgPrng(nil, 24, SECURITY_LEVEL_TEST, nil)
	if err == nil {
		t.Fatalf("expected error here")
	}
}

func Test_setZero(t *testing.T) {

	cases := []struct {
		name string
		args []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"normal", []byte{1, 2, 3, 4, 5}},
		{"large", bytes.Repeat([]byte{1, 2, 3, 4, 5}, 100)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			setZero(tt.args)
			if !bytes.Equal(tt.args, make([]byte, len(tt.args))) {
				t.Errorf("setZero() = %v, want %v", tt.args, make([]byte, len(tt.args)))
			}
		})
	}
}
