package zuc

import (
	"bytes"
	"strconv"
	"testing"
)

func TestChunkedCipherRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	iv := bytes.Repeat([]byte{0x11}, 16)
	chunkSize := 256 // small chunks for testing

	cc, err := NewChunkedCipher(key, iv, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 1000)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// encrypt chunk by chunk
	encrypted := make([]byte, len(plaintext))
	numChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	for ci := 0; ci < numChunks; ci++ {
		start := ci * chunkSize
		end := start + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if err := cc.XORChunk(encrypted[start:end], plaintext[start:end], uint64(ci)); err != nil {
			t.Fatal(err)
		}
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	// decrypt chunk by chunk
	decrypted := make([]byte, len(plaintext))
	for ci := 0; ci < numChunks; ci++ {
		start := ci * chunkSize
		end := start + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if err := cc.XORChunk(decrypted[start:end], encrypted[start:end], uint64(ci)); err != nil {
			t.Fatal(err)
		}
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted data should match plaintext")
	}
}

func TestChunkedXORKeyStreamAt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	iv := bytes.Repeat([]byte{0x11}, 16)
	chunkSize := 256

	cc, err := NewChunkedCipher(key, iv, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	dataSize := 2000
	plaintext := make([]byte, dataSize)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}

	// build expected keystream by encrypting zeros
	expected := make([]byte, dataSize)
	cc.XORKeyStreamAt(expected, plaintext, 0)

	t.Run("FullRange", func(t *testing.T) {
		dst := make([]byte, dataSize)
		cc.XORKeyStreamAt(dst, plaintext, 0)
		if !bytes.Equal(dst, expected) {
			t.Fatal("full range mismatch")
		}
	})

	t.Run("ChunkAligned", func(t *testing.T) {
		// read starting at chunk boundary
		offset := chunkSize
		dst := make([]byte, 500)
		cc.XORKeyStreamAt(dst, plaintext[offset:offset+500], uint64(offset))
		if !bytes.Equal(dst, expected[offset:offset+500]) {
			t.Fatal("chunk-aligned offset mismatch")
		}
	})

	t.Run("UnalignedOffset", func(t *testing.T) {
		offset := chunkSize + 37
		length := 500
		dst := make([]byte, length)
		cc.XORKeyStreamAt(dst, plaintext[offset:offset+length], uint64(offset))
		if !bytes.Equal(dst, expected[offset:offset+length]) {
			t.Fatal("unaligned offset mismatch")
		}
	})

	t.Run("CrossChunkBoundary", func(t *testing.T) {
		// read across chunk boundary
		offset := chunkSize - 50
		length := 200
		dst := make([]byte, length)
		cc.XORKeyStreamAt(dst, plaintext[offset:offset+length], uint64(offset))
		if !bytes.Equal(dst, expected[offset:offset+length]) {
			t.Fatal("cross-chunk boundary mismatch")
		}
	})

	t.Run("SmallRead", func(t *testing.T) {
		for _, offset := range []int{0, 1, 127, 128, 255, 256, 257, 511, 512, 999} {
			length := 1
			if offset+length > dataSize {
				continue
			}
			dst := make([]byte, length)
			cc.XORKeyStreamAt(dst, plaintext[offset:offset+length], uint64(offset))
			if !bytes.Equal(dst, expected[offset:offset+length]) {
				t.Fatalf("small read mismatch at offset %d", offset)
			}
		}
	})

	t.Run("Stateless", func(t *testing.T) {
		// calling same offset twice should give identical results
		dst1 := make([]byte, 300)
		dst2 := make([]byte, 300)
		offset := uint64(500)
		cc.XORKeyStreamAt(dst1, plaintext[offset:offset+300], offset)
		cc.XORKeyStreamAt(dst2, plaintext[offset:offset+300], offset)
		if !bytes.Equal(dst1, dst2) {
			t.Fatal("stateless calls should be deterministic")
		}
	})

	t.Run("ReverseOrder", func(t *testing.T) {
		// decrypt in reverse chunk order
		dst := make([]byte, dataSize)
		for ci := numChunks(dataSize, chunkSize) - 1; ci >= 0; ci-- {
			start := ci * chunkSize
			end := start + chunkSize
			if end > dataSize {
				end = dataSize
			}
			cc.XORKeyStreamAt(dst[start:end], plaintext[start:end], uint64(start))
		}
		if !bytes.Equal(dst, expected) {
			t.Fatal("reverse order mismatch")
		}
	})
}

func numChunks(dataSize, chunkSize int) int {
	return (dataSize + chunkSize - 1) / chunkSize
}

func TestChunkedCipherZUC256(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x11}, 23)
	chunkSize := 128

	cc, err := NewChunkedCipher(key, iv, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 500)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	encrypted := make([]byte, len(plaintext))
	cc.XORKeyStreamAt(encrypted, plaintext, 0)

	decrypted := make([]byte, len(plaintext))
	cc.XORKeyStreamAt(decrypted, encrypted, 0)

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("ZUC-256 roundtrip failed")
	}
}

func TestChunkedCipherInvalidParams(t *testing.T) {
	t.Run("BadKeySize", func(t *testing.T) {
		_, err := NewChunkedCipher(make([]byte, 15), make([]byte, 16), 0)
		if err == nil {
			t.Fatal("expected error for invalid key size")
		}
	})

	t.Run("BadIVSize", func(t *testing.T) {
		_, err := NewChunkedCipher(make([]byte, 16), make([]byte, 15), 0)
		if err == nil {
			t.Fatal("expected error for invalid IV size")
		}
	})

	t.Run("DefaultChunkSize", func(t *testing.T) {
		cc, err := NewChunkedCipher(make([]byte, 16), make([]byte, 16), 0)
		if err != nil {
			t.Fatal(err)
		}
		if cc.ChunkSize() != DefaultChunkSize {
			t.Fatalf("expected default chunk size %d, got %d", DefaultChunkSize, cc.ChunkSize())
		}
	})
}

func TestChunkedCipherEmptyData(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	iv := bytes.Repeat([]byte{0x11}, 16)
	cc, _ := NewChunkedCipher(key, iv, 128)

	// empty XORKeyStreamAt should not panic
	cc.XORKeyStreamAt(nil, nil, 0)
	cc.XORKeyStreamAt([]byte{}, []byte{}, 100)

	// empty XORChunk should not panic
	if err := cc.XORChunk(nil, nil, 0); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkChunkedXORKeyStreamAt(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	cc, _ := NewChunkedCipher(key, iv, 4096)

	for _, size := range []int{1024, 8192, 65536} {
		data := make([]byte, size)
		dst := make([]byte, size)
		b.Run(formatSize(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cc.XORKeyStreamAt(dst, data, 0)
			}
		})
	}
}

func BenchmarkChunkedRange(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	cc, _ := NewChunkedCipher(key, iv, 65536)

	data := make([]byte, 16384)
	dst := make([]byte, len(data))

	for _, offset := range []uint64{0, 100000, 1000000} {
		b.Run(formatSize(int(offset)), func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cc.XORKeyStreamAt(dst, data, offset)
			}
		})
	}
}

func BenchmarkChunkedVsSeekable(b *testing.B) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	data := make([]byte, 8192)
	dst := make([]byte, len(data))
	offset := uint64(100000)

	b.Run("Chunked_4K", func(b *testing.B) {
		cc, _ := NewChunkedCipher(key, iv, 4096)
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cc.XORKeyStreamAt(dst, data, offset)
		}
	})

	b.Run("Seekable_Bucket4K", func(b *testing.B) {
		sc, _ := NewCipherWithBucketSize(key, iv, 4096)
		// pre-fill states
		fill := make([]byte, offset+uint64(sc.bucketSize))
		sc.XORKeyStream(fill, fill)
		sc.reset(0)
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sc.XORKeyStreamAt(dst, data, offset)
		}
	})

	b.Run("Seekable_NoBucket", func(b *testing.B) {
		sc, _ := NewCipher(key, iv)
		b.SetBytes(int64(len(data)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sc.XORKeyStreamAt(dst, data, offset)
		}
	})
}

func formatSize(n int) string {
	switch {
	case n >= 1024*1024:
		return strconv.Itoa(n/1024/1024) + "M"
	case n >= 1024:
		return strconv.Itoa(n/1024) + "K"
	default:
		return strconv.Itoa(n) + "B"
	}
}
