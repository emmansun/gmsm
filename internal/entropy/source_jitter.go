// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import (
	"sync/atomic"
	"unsafe"
)

// ScratchBuffer is a large buffer that will be written to using atomics, to
// generate noise from memory access timings. Its contents do not matter.
type ScratchBuffer [1 << 25]byte // 32 MB

// jitterSource collects entropy from CPU timing jitter and memory access noise.
type jitterSource struct {
	memory   *ScratchBuffer
	lcgState uint32
	previous int64
}

func newJitterSource(memory *ScratchBuffer) *jitterSource {
	now := highResolutionTime()
	return &jitterSource{
		memory:   memory,
		lcgState: uint32(now),
		previous: now,
	}
}

// touchMemory performs a write to memory at the given index.
// The memory slice is shared across sources to avoid the significant (~500µs)
// cost of zeroing a new allocation on every Seed call.
func touchMemory(memory *ScratchBuffer, idx uint32) {
	idx = idx / 4 * 4 // align to 32 bits
	u32 := (*uint32)(unsafe.Pointer(&memory[idx]))
	last := atomic.LoadUint32(u32)
	atomic.SwapUint32(u32, last+13)
}

// sample measures timing jitter from one round of memory accesses.
func (s *jitterSource) sample() uint8 {
	// Perform memory accesses in an unpredictable pattern to expose the
	// next measurement to as much system noise as possible.
	memory, lcgState := s.memory, s.lcgState
	if memory == nil {
		panic("entropy: nil memory buffer")
	}
	for range 64 {
		lcgState = 1664525*lcgState + 1013904223
		// Discard the lower bits, which tend to fall into short cycles.
		idx := (lcgState >> 6) & (1<<25 - 1)
		touchMemory(memory, idx)
	}
	s.lcgState = lcgState

	t := highResolutionTime()
	// Use platform-specific high-resolution timer.
	sample := t - s.previous
	s.previous = t

	// Reduce the symbol space to 256 values, assuming most of the entropy is in
	// the least-significant bits, which represent the highest-resolution timing
	// differences.
	return uint8(sample)
}

// collectJitterSamples starts a new jitter entropy source, collects the requested
// number of samples, conducts startup health tests, and returns the samples or
// an error if the health tests fail.
func collectJitterSamples(samples []uint8, memory *ScratchBuffer) error {
	if len(samples) < 1024 {
		return errInsufficientSamples
	}
	s := newJitterSource(memory)
	// Warm up the source to avoid any initial bias.
	for range 4 {
		_ = s.sample()
	}
	for i := range samples {
		samples[i] = s.sample()
	}
	if err := RepetitionCountTest(samples); err != nil {
		return err
	}
	if err := AdaptiveProportionTest(samples); err != nil {
		return err
	}
	if err := LagPredictorTest(samples); err != nil {
		return err
	}
	return nil
}
