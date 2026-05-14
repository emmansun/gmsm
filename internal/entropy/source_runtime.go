// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import (
	"hash"
	"runtime"

	"github.com/emmansun/gmsm/internal/sm3"
)

// hashLoopSource collects entropy from SM3 hash computation timing combined
// with goroutine scheduling jitter.
//
// Each sample does two things independently:
//  1. SM3 hash loop: runs hashLoopIterations of chained SM3 to expose CPU
//     micro-architectural timing variation (pipeline stalls, cache state,
//     branch prediction, frequency scaling).
//  2. Goroutine yield: a single runtime.Gosched() call introduces scheduling
//     jitter that is unpredictable and depends on system load, making this
//     source independent of the memory-access jitter source (source_jitter.go).
//
// The goroutine yield ensures reliable timing variation even on systems where
// the timer resolution exceeds the hash computation time (e.g., Windows with
// 100ns QPC resolution and fast AVX2 SM3 execution).
//
// Inspired by the "hash loop" noise source in jitterentropy-library
// (Stephan Müller), adapted to use SM3 and augmented with scheduling jitter
// for cross-platform reliability.
type hashLoopSource struct {
	previous int64
	state    [sm3.Size]byte // chaining state updated each sample
	h        hash.Hash      // reused SM3 hasher, reset each iteration
}

func newHashLoopSource() *hashLoopSource {
	t := highResolutionTime()
	s := &hashLoopSource{
		previous: t,
		h:        sm3.New(),
	}
	// Seed initial state from the current timer to ensure goroutines started
	// concurrently have different initial states, computing different hash
	// chains and accessing different cache lines.
	s.state[0] = byte(t)
	s.state[1] = byte(t >> 8)
	s.state[2] = byte(t >> 16)
	s.state[3] = byte(t >> 24)
	return s
}

// hashLoopIterations is the number of SM3 computations per sample.
// 16 iterations create sufficient CPU micro-architectural state perturbation
// while keeping the computation time moderate.
const hashLoopIterations = 16

// sample measures timing jitter from SM3 hash computation and goroutine
// scheduling. The internal state is updated each call so successive inputs
// differ, preventing CPU caches from hiding genuine timing variation.
func (s *hashLoopSource) sample() uint8 {
	h := s.h
	// state is a 32-byte slice backed by s.state. Each h.Sum(state[:0])
	// call writes the digest back into s.state in-place (no allocation).
	state := s.state[:]
	for range hashLoopIterations {
		h.Reset()
		h.Write(state)
		state = h.Sum(state[:0])
	}

	// Yield to the scheduler: this introduces timing jitter from goroutine
	// scheduling unpredictability, ensuring good distribution of time deltas
	// even on systems where the timer resolution exceeds the hash loop time.
	runtime.Gosched()

	t := highResolutionTime()
	sample := t - s.previous
	s.previous = t

	return uint8(sample)
}

// collectRuntimeSamples collects entropy samples from hash loop timing noise,
// conducts startup health tests, and returns the samples or an error
// if the health tests fail.
func collectRuntimeSamples(samples []uint8) error {
	if len(samples) < 1024 {
		return errInsufficientSamples
	}
	s := newHashLoopSource()
	// Warm up: discard early samples to allow the CPU to reach a
	// steady micro-architectural state (branch predictors, L1 cache).
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
