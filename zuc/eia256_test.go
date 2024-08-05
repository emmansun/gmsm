package zuc

import (
	"encoding/hex"
	"hash"
	"testing"

	"github.com/emmansun/gmsm/internal/cryptotest"
)

var zucEIA256Tests = []struct {
	key    []byte
	iv     []byte
	msg    []byte
	nMsgs  int
	mac32  string
	mac64  string
	mac128 string
}{
	{
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		1,
		"9b972a74",
		"673e54990034d38c",
		"d85e54bbcb9600967084c952a1654b26",
	},
	{
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		[]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		10,
		"8754f5cf",
		"130dc225e72240cc",
		"df1e8307b31cc62beca1ac6f8190c22f",
	},
	{
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		[]byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		1,
		"1f3079b4",
		"8c71394d39957725",
		"a35bb274b567c48b28319f111af34fbd",
	},
	{
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		[]byte{
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		10,
		"5c7c8b88",
		"ea1dee544bb6223b",
		"3a83b554be408ca5494124ed9d473205",
	},
}

func TestEIA_Finish256_32(t *testing.T) {
	for i, test := range zucEIA256Tests {
		h, err := NewHash256(test.key, test.iv, 4)
		if err != nil {
			t.Error(err)
		}
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest := h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac32 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac32, hex.EncodeToString(digest))
		}
		h.Reset()
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest = h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac32 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac32, hex.EncodeToString(digest))
		}
	}
}

func TestEIA_Finish256_64(t *testing.T) {
	for i, test := range zucEIA256Tests {
		h, err := NewHash256(test.key, test.iv, 8)
		if err != nil {
			t.Error(err)
		}
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest := h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac64 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac64, hex.EncodeToString(digest))
		}
		h.Reset()
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest = h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac64 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac64, hex.EncodeToString(digest))
		}
	}
}

func TestEIA_Finish256_128(t *testing.T) {
	for i, test := range zucEIA256Tests {
		h, err := NewHash256(test.key, test.iv, 16)
		if err != nil {
			t.Error(err)
		}
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest := h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac128 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac128, hex.EncodeToString(digest))
		}
		h.Reset()
		for j := 0; j < test.nMsgs; j++ {
			_, err = h.Write(test.msg)
			if err != nil {
				t.Error(err)
			}
		}
		digest = h.Sum(nil)
		if hex.EncodeToString(digest) != test.mac128 {
			t.Errorf("case %d, expected=%s, result=%s\n", i+1, test.mac128, hex.EncodeToString(digest))
		}
	}
}

func TestEIA256_Sum32(t *testing.T) {
	expected := "f4f20d7c"
	h, err := NewHash256(zucEIA256Tests[2].key, zucEIA256Tests[2].iv, 4)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Write([]byte("emmansun"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Write([]byte("shangmi1"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Write([]byte("emmansun shangmi"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Write([]byte("emmansun shangmi 1234"))
	if err != nil {
		t.Fatal(err)
	}
	mac := h.Sum(nil)
	if hex.EncodeToString(mac) != expected {
		t.Errorf("expected=%s, result=%s\n", expected, hex.EncodeToString(mac))
	}
}

func TestEIA256_Finish(t *testing.T) {
	expected := []struct {
		expected string
		macLen   int
	}{
		{
			"9dd592c4",
			4,
		},
		{
			"1f6f71e386a2ce01",
			8,
		},
		{
			"bf5339cfd87bba97d70ef4f5973af8bb",
			16,
		},
	}
	for _, exp := range expected {
		h, err := NewHash256(zucEIA256Tests[2].key, zucEIA256Tests[2].iv, exp.macLen)
		if err != nil {
			t.Fatal(err)
		}
		mac := h.Finish([]byte("emmansunshangmi1emmansun shangmiemmansun shangmi 12345"), 8*53+4)
		if hex.EncodeToString(mac) != exp.expected {
			t.Errorf("expected=%s, result=%s\n", exp.expected, hex.EncodeToString(mac))
		}
	}
}

func TestEIA256Hash(t *testing.T) {
	t.Run("EIA-256-32", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash {
			h, _ := NewHash256(zucEIA256Tests[0].key, zucEIA256Tests[0].iv, 4)
			return h
		})
	})
	t.Run("EIA-256-64", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash {
			h, _ := NewHash256(zucEIA256Tests[0].key, zucEIA256Tests[0].iv, 8)
			return h
		})
	})
	t.Run("EIA-256-128", func(t *testing.T) {
		cryptotest.TestHash(t, func() hash.Hash {
			h, _ := NewHash256(zucEIA256Tests[0].key, zucEIA256Tests[0].iv, 16)
			return h
		})
	})
}

func benchmark256Size(b *testing.B, size, tagSize int) {
	var key [32]byte
	var iv [23]byte
	var buf = make([]byte, 8192)
	bench, _ := NewHash256(key[:], iv[:], tagSize)
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes_Tag32(b *testing.B) {
	benchmark256Size(b, 8, 4)
}

func BenchmarkHash8Bytes_Tag64(b *testing.B) {
	benchmark256Size(b, 8, 8)
}

func BenchmarkHash8Bytes_Tag128(b *testing.B) {
	benchmark256Size(b, 8, 16)
}

func BenchmarkHash1K_Tag32(b *testing.B) {
	benchmark256Size(b, 1024, 4)
}

func BenchmarkHash1K_Tag64(b *testing.B) {
	benchmark256Size(b, 1024, 8)
}

func BenchmarkHash1K_Tag128(b *testing.B) {
	benchmark256Size(b, 1024, 16)
}

func BenchmarkHash8K_Tag32(b *testing.B) {
	benchmark256Size(b, 8192, 4)
}

func BenchmarkHash8K_Tag64(b *testing.B) {
	benchmark256Size(b, 8192, 8)
}

func BenchmarkHash8K_Tag128(b *testing.B) {
	benchmark256Size(b, 8192, 16)
}
