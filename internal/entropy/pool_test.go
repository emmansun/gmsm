package entropy

import (
	"testing"
)

func TestPool_ExtractInsufficientEntropy(t *testing.T) {
	var p entropyPool

	// Add entropy below minEntropyBits threshold.
	input := make([]byte, 16)
	p.add(input, 128) // 128 < 256

	defer func() {
		if r := recover(); r == nil {
			t.Error("extract with insufficient entropy did not panic")
		}
	}()
	p.extract()
}

func TestPool_AddAndExtract(t *testing.T) {
	var p entropyPool

	// Add enough entropy to exceed minEntropyBits.
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i)
	}
	p.add(input, 512)

	if p.entropy != 512 {
		t.Fatalf("entropy = %d, want 512", p.entropy)
	}

	seed := p.extract()

	// Seed should not be all zeros.
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("extract returned all-zero seed")
	}

	// After extraction, entropy should be reset.
	if p.entropy != 0 {
		t.Errorf("entropy after extract = %d, want 0", p.entropy)
	}
}

func TestPool_ForwardSecrecy(t *testing.T) {
	// Two pools with identical state should produce different seeds
	// after the first extraction due to feedback.
	var p1, p2 entropyPool

	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i)
	}
	p1.add(input, 512)
	p2.add(input, 512)

	seed1a := p1.extract()
	seed2a := p2.extract()

	// First extraction should be identical (same state).
	if seed1a != seed2a {
		t.Error("identical pools produced different first seeds")
	}

	// Add same entropy to both, second extraction should differ
	// because feedback from first extraction changed pool state.
	// Actually, since feedback is deterministic and both got same seed,
	// the pools are still in the same state. Add same input again.
	p1.add(input, 512)
	p2.add(input, 512)

	seed1b := p1.extract()
	seed2b := p2.extract()

	// Still same because both pools followed identical paths.
	if seed1b != seed2b {
		t.Error("identical pools diverged unexpectedly")
	}

	// But consecutive extractions from the same pool should differ
	// even with the same input, because feedback changes pool state.
	var p3 entropyPool
	p3.add(input, 512)
	first := p3.extract()

	p3.add(input, 512)
	second := p3.extract()

	if first == second {
		t.Error("consecutive extractions with same input produced identical seeds")
	}
}

func TestPool_DifferentInputs(t *testing.T) {
	var p1, p2 entropyPool

	input1 := make([]byte, 64)
	input2 := make([]byte, 64)
	for i := range input1 {
		input1[i] = byte(i)
		input2[i] = byte(i + 1)
	}

	p1.add(input1, 512)
	p2.add(input2, 512)

	seed1 := p1.extract()
	seed2 := p2.extract()

	if seed1 == seed2 {
		t.Error("different inputs produced same seed")
	}
}

func TestPool_EntropyCap(t *testing.T) {
	var p entropyPool

	// Add more entropy bits than pool capacity.
	large := make([]byte, 256)
	p.add(large, poolBytes*8+1000)

	if p.entropy != poolBytes*8 {
		t.Errorf("entropy = %d, want cap at %d", p.entropy, poolBytes*8)
	}
}

func TestPool_CircularWrap(t *testing.T) {
	var p entropyPool

	// Add more words than pool capacity to test circular wrapping.
	// poolWords=128, each word is 4 bytes. Adding 132*4=528 bytes = 132 words.
	input := make([]byte, (poolWords+4)*4)
	for i := range input {
		input[i] = byte(i)
	}
	p.add(input, 512)

	if p.pos != 4 {
		t.Errorf("pos after wraparound = %d, want 4", p.pos)
	}

	seed := p.extract()

	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("extract after wraparound returned all-zero seed")
	}
}

func BenchmarkPoolAdd(b *testing.B) {
	var p entropyPool
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i)
	}
	b.ResetTimer()
	for b.Loop() {
		p.add(input, 1024)
	}
}

func BenchmarkPoolExtract(b *testing.B) {
	var p entropyPool
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i)
	}
	p.add(input, 1024)
	b.ResetTimer()
	for b.Loop() {
		p.add(input, 1024) // re-add entropy for each extraction
		p.extract()
	}
}
