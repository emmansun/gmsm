package entropy

import (
	"testing"
)

func TestReadOSEntropy(t *testing.T) {
	buf := make([]byte, 32)
	readOSEntropy(buf)

	// Check it's not all zeros (astronomically unlikely with real randomness).
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("readOSEntropy returned all zeros")
	}
}

func TestCollectJitterSamples(t *testing.T) {
	var memory ScratchBuffer
	samples := make([]uint8, 1024)
	err := collectJitterSamples(samples, &memory)
	if err != nil {
		t.Fatalf("collectJitterSamples failed: %v", err)
	}

	// Basic check: not all samples should be the same value.
	first := samples[0]
	allSame := true
	for _, s := range samples[1:] {
		if s != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("collectJitterSamples produced all identical samples")
	}
}

func TestCollectJitterSamples_TooFew(t *testing.T) {
	var memory ScratchBuffer
	samples := make([]uint8, 512)
	err := collectJitterSamples(samples, &memory)
	if err == nil {
		t.Error("collectJitterSamples should fail with fewer than 1024 samples")
	}
}

func TestCollectRuntimeSamples(t *testing.T) {
	samples := make([]uint8, 1024)
	err := collectRuntimeSamples(samples)
	if err != nil {
		t.Fatalf("collectRuntimeSamples failed: %v", err)
	}

	// Basic check: not all samples should be the same value.
	first := samples[0]
	allSame := true
	for _, s := range samples[1:] {
		if s != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("collectRuntimeSamples produced all identical samples")
	}
}

func TestCollectRuntimeSamples_TooFew(t *testing.T) {
	samples := make([]uint8, 512)
	err := collectRuntimeSamples(samples)
	if err == nil {
		t.Error("collectRuntimeSamples should fail with fewer than 1024 samples")
	}
}
