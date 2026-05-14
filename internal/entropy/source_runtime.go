// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import (
	"runtime"

	"github.com/emmansun/gmsm/internal/sm3"
)

// runtimeSource collects entropy from Go runtime scheduling jitter,
// memory allocation timing, and hash computation timing.
type runtimeSource struct {
	previous int64
	counter  uint32
}

func newRuntimeSource() *runtimeSource {
	return &runtimeSource{
		previous: highResolutionTime(),
	}
}

// sample measures timing jitter from runtime operations:
// goroutine scheduling yield, memory allocation, and SM3 computation.
func (s *runtimeSource) sample() uint8 {
	s.counter++

	// Yield to the scheduler — timing depends on system load and
	// other goroutines competing for CPU time.
	runtime.Gosched()

	// Vary allocation size to create different allocator paths.
	// Different sizes hit different size classes in the allocator.
	allocSize := 16 + (s.counter%48)*8
	buf := make([]byte, allocSize)

	// SM3 computation over varying data — timing depends on CPU
	// pipeline state, cache state, and data content.
	h := sm3.New()
	buf[0] = byte(s.counter)
	h.Write(buf)
	h.Sum(buf[:0])

	// Multiple goroutine yields to accumulate scheduling noise.
	for range s.counter % 4 {
		runtime.Gosched()
	}

	// Use high-resolution timer for precise monotonic measurement.
	t := highResolutionTime()
	sample := t - s.previous
	s.previous = t

	return uint8(sample)
}

// collectRuntimeSamples collects entropy samples from runtime noise,
// conducts startup health tests, and returns the samples or an error
// if the health tests fail.
func collectRuntimeSamples(samples []uint8) error {
	if len(samples) < 1024 {
		return errInsufficientSamples
	}
	s := newRuntimeSource()
	// Warm up.
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
	return nil
}
