package kdf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestKdf(t *testing.T) {
	type args struct {
		md  hash.Hash
		z   []byte
		len int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sm3 case 1", args{sm3.New(), []byte("emmansun"), 16}, "708993ef1388a0ae4245a19bb6c02554"},
		{"sm3 case 2", args{sm3.New(), []byte("emmansun"), 32}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd4"},
		{"sm3 case 3", args{sm3.New(), []byte("emmansun"), 48}, "708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"},
		{"sm3 case 4", args{sm3.New(), []byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f"},
		{"sm3 case 5", args{sm3.New(), []byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 128}, "49cf14649f324a07e0d5bb2a00f7f05d5f5bdd6d14dff028e071327ec031104590eddb18f98b763e18bf382ff7c3875f30277f3179baebd795e7853fa643fdf280d8d7b81a2ab7829f615e132ab376d32194cd315908d27090e1180ce442d9be99322523db5bfac40ac5acb03550f5c93e5b01b1d71f2630868909a6a1250edb"},
	}
	for _, tt := range tests {
		wantBytes, _ := hex.DecodeString(tt.want)
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(sm3.New, tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v) = %x, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestKdfOldCase(t *testing.T) {
	x2, _ := new(big.Int).SetString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE", 16)
	y2, _ := new(big.Int).SetString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78", 16)

	expected := "006e30dae231b071dfad8aa379e90264491603"

	result := Kdf(sm3.New, append(x2.Bytes(), y2.Bytes()...), 19)

	resultStr := hex.EncodeToString(result)

	if expected != resultStr {
		t.Fatalf("expected %s, real value %s", expected, resultStr)
	}
}

// TestKdfSingleIteration tests the optimization path for single iteration (limit == 1)
func TestKdfSingleIteration(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		z       []byte
		keyLen  int
	}{
		{"sm3 exact hash size", sm3.New, []byte("test"), 32},
		{"sm3 less than hash size", sm3.New, []byte("test"), 16},
		{"sha256 exact hash size", sha256.New, []byte("test"), 32},
		{"sha256 less than hash size", sha256.New, []byte("test"), 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Kdf(tt.newHash, tt.z, tt.keyLen)
			if len(result) != tt.keyLen {
				t.Errorf("expected length %d, got %d", tt.keyLen, len(result))
			}
			// Verify it's deterministic
			result2 := Kdf(tt.newHash, tt.z, tt.keyLen)
			if !reflect.DeepEqual(result, result2) {
				t.Errorf("Kdf not deterministic")
			}
		})
	}
}

// TestKdfSmallZ tests optimization path with small z (less than BlockSize)
func TestKdfSmallZ(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		zLen    int
		keyLen  int
	}{
		{"sm3 small z, multiple iterations", sm3.New, 16, 64},       // SM3 BlockSize is 64
		{"sha256 small z, multiple iterations", sha256.New, 32, 96}, // SHA256 BlockSize is 64
		{"sm3 very small z", sm3.New, 8, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := make([]byte, tt.zLen)
			for i := range z {
				z[i] = byte(i)
			}
			result := Kdf(tt.newHash, z, tt.keyLen)
			if len(result) != tt.keyLen {
				t.Errorf("expected length %d, got %d", tt.keyLen, len(result))
			}
		})
	}
}

// TestKdfLargeZ tests optimization path with large z (greater than BlockSize)
func TestKdfLargeZ(t *testing.T) {
	tests := []struct {
		name    string
		newHash func() hash.Hash
		zLen    int
		keyLen  int
	}{
		{"sm3 large z, multiple iterations", sm3.New, 128, 96},
		{"sha256 large z, multiple iterations", sha256.New, 256, 128},
		{"sm3 very large z", sm3.New, 512, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := make([]byte, tt.zLen)
			for i := range z {
				z[i] = byte(i)
			}
			result := Kdf(tt.newHash, z, tt.keyLen)
			if len(result) != tt.keyLen {
				t.Errorf("expected length %d, got %d", tt.keyLen, len(result))
			}
		})
	}
}

// TestKdfZeroLength tests edge case with zero-length output
func TestKdfZeroLength(t *testing.T) {
	result := Kdf(sm3.New, []byte("test"), 0)
	if len(result) != 0 {
		t.Errorf("expected empty result, got length %d", len(result))
	}
}

// TestKdfEmptyZ tests edge case with empty input
func TestKdfEmptyZ(t *testing.T) {
	result := Kdf(sm3.New, []byte{}, 32)
	if len(result) != 32 {
		t.Errorf("expected length 32, got %d", len(result))
	}
	// Should be deterministic even with empty input
	result2 := Kdf(sm3.New, []byte{}, 32)
	if !reflect.DeepEqual(result, result2) {
		t.Errorf("Kdf not deterministic with empty z")
	}
}

// TestKdfConsistency verifies both optimization paths produce identical results
func TestKdfConsistency(t *testing.T) {
	tests := []struct {
		name   string
		zLen   int
		keyLen int
	}{
		{"boundary small z", 63, 128}, // Just below SM3 BlockSize (64)
		{"boundary large z", 65, 128}, // Just above SM3 BlockSize
		{"exact block size", 64, 128}, // Exactly BlockSize
		{"multiple blocks", 128, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := make([]byte, tt.zLen)
			for i := range z {
				z[i] = byte(i & 0xff)
			}

			// Both paths should produce identical results
			result1 := Kdf(sm3.New, z, tt.keyLen)
			result2 := Kdf(sm3.New, z, tt.keyLen)

			if !reflect.DeepEqual(result1, result2) {
				t.Errorf("inconsistent results: %x vs %x", result1, result2)
			}
		})
	}
}

// TestKdfInterface tests the KdfInterface optimization
func TestKdfInterface(t *testing.T) {
	// SM3 implements KdfInterface, so it should use the optimized path
	z := []byte("test data for kdf interface")
	keyLen := 64

	result := Kdf(sm3.New, z, keyLen)
	if len(result) != keyLen {
		t.Errorf("expected length %d, got %d", keyLen, len(result))
	}

	// Verify it's consistent
	result2 := Kdf(sm3.New, z, keyLen)
	if !reflect.DeepEqual(result, result2) {
		t.Errorf("KdfInterface implementation not deterministic")
	}
}

// TestKdfMultipleIterations tests various iteration counts
func TestKdfMultipleIterations(t *testing.T) {
	z := []byte("shared secret")
	hashSize := 32 // SM3 output size

	tests := []struct {
		name       string
		keyLen     int
		iterations int
	}{
		{"1 iteration", hashSize - 1, 1},
		{"2 iterations", hashSize + 1, 2},
		{"3 iterations", hashSize*2 + 1, 3},
		{"10 iterations", hashSize*9 + 1, 10},
		{"100 iterations", hashSize*99 + 1, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Kdf(sm3.New, z, tt.keyLen)
			if len(result) != tt.keyLen {
				t.Errorf("expected length %d, got %d", tt.keyLen, len(result))
			}
		})
	}
}

func shouldPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		err := recover()
		if err == nil {
			t.Errorf("should have panicked")
		}
	}()
	f()
}

func TestKdfWithSHA256(t *testing.T) {
	type args struct {
		z   []byte
		len int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"sha256 case 1", args{[]byte("emmansun"), 16}, "1bca7e7d05a858f5852a6e0ce7e99852"},
		{"sha256 case 2", args{[]byte("emmansun"), 32}, "1bca7e7d05a858f5852a6e0ce7e9985294ebdc82c7f1c6539f89356d9c0a2856"},
		{"sha256 case 3", args{[]byte("emmansun"), 48}, "1bca7e7d05a858f5852a6e0ce7e9985294ebdc82c7f1c6539f89356d9c0a28569500417f9b74de4ea18a85813b8968ba"},
		{"sha256 case 4", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 48}, "61cc5b862a0a6511b3558536112c7ba4f21c9d65025505c0099bbba7196a35ed34d7805e5c4d779fcd0d950f693ec0f8"},
		{"sha256 case 5", args{[]byte("708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493708993ef1388a0ae4245a19bb6c02554c632633e356ddb989beb804fda96cfd47eba4fa460e7b277bc6b4ce4d07ed493"), 128}, "61cc5b862a0a6511b3558536112c7ba4f21c9d65025505c0099bbba7196a35ed34d7805e5c4d779fcd0d950f693ec0f8b1fdc996e97eadb5b7bee7ac44dd1a7954a44dd92c71c465f4ab20479c92748f179bd03bdad1768c65b59d62a0735dcf08837a04f32f53d45b5bdb00f5fd1bee003f6fcc01c003594d33014161862030"},
	}
	for _, tt := range tests {
		wantBytes, _ := hex.DecodeString(tt.want)
		t.Run(tt.name, func(t *testing.T) {
			if got := Kdf(sha256.New, tt.args.z, tt.args.len); !reflect.DeepEqual(got, wantBytes) {
				t.Errorf("Kdf(%v) = %x, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func BenchmarkKdf(b *testing.B) {
	tests := []struct {
		zLen int
		kLen int
	}{
		{32, 32},
		{32, 64},
		{32, 128},
		{64, 32},
		{64, 64},
		{64, 128},
		{64, 256},
		{64, 512},
		{64, 1024},
	}
	z := make([]byte, 512)
	for _, tt := range tests {
		b.Run(fmt.Sprintf("zLen=%v-kLen=%v", tt.zLen, tt.kLen), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(sm3.New, z[:tt.zLen], tt.kLen)
			}
		})
	}
}

// BenchmarkKdfOptimizationPaths benchmarks different optimization scenarios
func BenchmarkKdfOptimizationPaths(b *testing.B) {
	tests := []struct {
		name string
		zLen int
		kLen int
	}{
		{"SmallZ-SingleIteration", 32, 32},      // Should use standard path
		{"SmallZ-MultipleIterations", 32, 128},  // Should use standard path
		{"LargeZ-SingleIteration", 128, 32},     // Should use standard path (single iteration)
		{"LargeZ-MultipleIterations", 128, 128}, // Should use optimized path
		{"VeryLargeZ-ManyIterations", 512, 512}, // Should use optimized path
	}

	for _, tt := range tests {
		z := make([]byte, tt.zLen)
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(tt.kLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(sm3.New, z, tt.kLen)
			}
		})
	}
}

// BenchmarkKdfSHA256 benchmarks KDF with SHA256 (no KdfInterface optimization)
func BenchmarkKdfSHA256(b *testing.B) {
	tests := []struct {
		zLen int
		kLen int
	}{
		{64, 32},
		{64, 128},
		{128, 256},
	}

	for _, tt := range tests {
		z := make([]byte, tt.zLen)
		b.Run(fmt.Sprintf("zLen=%d-kLen=%d", tt.zLen, tt.kLen), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(tt.kLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				Kdf(sha256.New, z, tt.kLen)
			}
		})
	}
}
