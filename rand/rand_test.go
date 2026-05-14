package rand

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/emmansun/gmsm/drbg"
)

func TestRead(t *testing.T) {
	buf := make([]byte, 64)
	n, err := Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 64 {
		t.Fatalf("Read returned %d bytes, want 64", n)
	}
	if bytes.Equal(buf, make([]byte, 64)) {
		t.Error("Read returned all zeros")
	}
}

func TestRead_Empty(t *testing.T) {
	n, err := Read(nil)
	if err != nil {
		t.Fatalf("Read(nil) failed: %v", err)
	}
	if n != 0 {
		t.Fatalf("Read(nil) returned %d, want 0", n)
	}

	n, err = Read([]byte{})
	if err != nil {
		t.Fatalf("Read(empty) failed: %v", err)
	}
	if n != 0 {
		t.Fatalf("Read(empty) returned %d, want 0", n)
	}
}

func TestRead_LargeBuffer(t *testing.T) {
	buf := make([]byte, 4096)
	n, err := Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 4096 {
		t.Fatalf("Read returned %d bytes, want 4096", n)
	}
	if bytes.Equal(buf, make([]byte, 4096)) {
		t.Error("Read returned all zeros for large buffer")
	}
}

func TestRead_DifferentOutputs(t *testing.T) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	Read(buf1)
	Read(buf2)
	if bytes.Equal(buf1, buf2) {
		t.Error("two consecutive Read calls returned identical results")
	}
}

func TestReader(t *testing.T) {
	buf := make([]byte, 32)
	n, err := io.ReadFull(Reader, buf)
	if err != nil {
		t.Fatalf("Reader.Read failed: %v", err)
	}
	if n != 32 {
		t.Fatalf("Reader.Read returned %d bytes, want 32", n)
	}
	if bytes.Equal(buf, make([]byte, 32)) {
		t.Error("Reader returned all zeros")
	}
}

func TestRead_Concurrent(t *testing.T) {
	const goroutines = 20
	const bytesPerGoroutine = 256

	var wg sync.WaitGroup
	results := make([][]byte, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			buf := make([]byte, bytesPerGoroutine)
			n, err := Read(buf)
			if err != nil {
				t.Errorf("goroutine %d: Read failed: %v", idx, err)
				return
			}
			if n != bytesPerGoroutine {
				t.Errorf("goroutine %d: Read returned %d bytes, want %d", idx, n, bytesPerGoroutine)
				return
			}
			results[idx] = buf
		}(i)
	}
	wg.Wait()

	// Check that results are different.
	for i := 0; i < goroutines; i++ {
		for j := i + 1; j < goroutines; j++ {
			if results[i] != nil && results[j] != nil && bytes.Equal(results[i], results[j]) {
				t.Errorf("goroutines %d and %d produced identical output", i, j)
			}
		}
	}
}

func TestSelfTest(t *testing.T) {
	// selfTest panics on failure; if we reach here it passed.
	selfTest()
}

func TestRead_ReseedTrigger(t *testing.T) {
	// Use SECURITY_LEVEL_TEST which reseeds every 8 generates.
	// SM3 Hash DRBG GM mode produces max 32 bytes per Generate.
	// So reading 32*9 = 288 bytes should trigger at least one reseed.
	old := securityLevel.Load()
	securityLevel.Store(int32(drbg.SECURITY_LEVEL_TEST))
	defer securityLevel.Store(old)

	// Force a new DRBG with test-level security.
	d := newDRBG()
	drbgInstance.Store(d)

	buf := make([]byte, 288)
	n, err := Read(buf)
	if err != nil {
		t.Fatalf("Read with reseed failed: %v", err)
	}
	if n != 288 {
		t.Fatalf("Read returned %d bytes, want 288", n)
	}
	if bytes.Equal(buf, make([]byte, 288)) {
		t.Error("Read returned all zeros after reseed")
	}
}

func BenchmarkRead32(b *testing.B) {
	buf := make([]byte, 32)
	for b.Loop() {
		Read(buf)
	}
}

func BenchmarkRead1K(b *testing.B) {
	buf := make([]byte, 1024)
	for b.Loop() {
		Read(buf)
	}
}
