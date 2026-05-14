// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package entropy

import "sync"

// memory is a scratch buffer that is accessed between samples by the jitter
// entropy source to expose it to memory access timings.
//
// We reuse it and share it between Seed calls to avoid the significant (~500µs)
// cost of zeroing a new allocation every time. The entropy source accesses it
// using atomics (and doesn't care about its contents).
//
// It resides in the BSS segment and only becomes backed by physical pages
// at first use. Programs that do not call Seed do not incur any memory cost.
var memory ScratchBuffer

const (
	osEntropySize = 32   // bytes from OS source
	numSamples    = 1024 // base samples per non-OS source (minimum for SP 800-90B startup health tests)

	// maxOSR is the maximum over-sampling rate for adaptive collection.
	// When health tests fail at OSR n, sample count is doubled (n*numSamples)
	// until OSR reaches maxOSR. Beyond this, Seed panics.
	// This mirrors jitterentropy's adaptive OSR mechanism.
	maxOSR = 4

	// retriesPerOSR is the number of collection attempts at each OSR level
	// before escalating to the next (higher sample count) level.
	retriesPerOSR = 3

	// Conservative entropy estimates (bits) per source. These values
	// remain fixed regardless of the OSR — extra samples at higher OSR
	// compensate for lower per-sample entropy quality in weak environments,
	// but the credited entropy is always the conservative 1 bit/sample
	// lower bound applied to the base sample count.
	//
	// OS source: 8 bits per byte. The OS random source (crypto/rand.Reader)
	// produces fully conditioned output from the kernel CSPRNG. It is
	// standard practice to credit full entropy (8 bits/byte) to
	// well-maintained OS random devices (/dev/urandom, CryptGenRandom,
	// getrandom(2)). 32 bytes × 8 = 256 bits.
	//
	// CPU jitter source: 1 bit per sample. This is a conservative lower
	// bound per SP 800-90B min-entropy estimation. Actual entropy depends
	// on timer resolution, CPU microarchitecture, and system load. On
	// bare-metal systems with high-resolution timers, real entropy per
	// sample is typically higher (2-4 bits). In heavily virtualized or
	// resource-constrained environments (containers with CPU pinning,
	// VMs with coarse-grained timer virtualization), entropy per sample
	// may approach this lower bound.
	//
	// Hash loop source: 1 bit per sample. Similar conservative estimate.
	// Timing jitter from SM3 micro-architectural effects (pipeline stalls,
	// cache state, branch prediction, frequency variation) depends on
	// system micro-architectural state.
	osEntropyBits      = osEntropySize * 8 // 256 bits
	jitterEntropyBits  = numSamples        // 1024 bits (1 bit/sample conservative)
	runtimeEntropyBits = numSamples        // 1024 bits (1 bit/sample conservative)
)

// globalPool is the persistent entropy pool per GM/T 0105-2021 Section 5.3.
// It accumulates entropy across Seed() calls and provides forward secrecy
// by feeding extraction results back into the pool.
var globalPool struct {
	sync.Mutex
	pool entropyPool
}

// collectWithAdaptiveOSR collects entropy samples with an adaptive
// over-sampling rate (OSR). If health tests fail at the current OSR level,
// the sample count is doubled and collection is retried up to retriesPerOSR
// times before escalating. This mirrors the adaptive OSR mechanism in
// jitterentropy-library (Stephan Müller).
//
// Entropy credit for the collected samples is always jitterEntropyBits
// (base numSamples bits), regardless of OSR — extra samples at higher OSR
// compensate for weaker per-sample entropy in constrained environments.
//
// Panics if all OSR levels are exhausted, indicating the entropy source is
// unsuitable for this system.
func collectWithAdaptiveOSR(name string, collect func([]uint8) error) []uint8 {
	for osr := 1; osr <= maxOSR; osr++ {
		samples := make([]uint8, numSamples*osr)
		for range retriesPerOSR {
			if err := collect(samples); err == nil {
				return samples
			}
		}
	}
	panic("entropy: " + name + " entropy source failed health tests at maximum OSR")
}

// Seed collects entropy from three independent sources (OS randomness,
// CPU jitter, and hash loop noise), feeds them into the entropy pool,
// runs SP 800-90B health tests on the non-OS sources, and extracts a
// conditioned seed for DRBG instantiation.
//
// The entropy pool uses a circular shift register (per GM/T 0105-2021
// Appendix A.3) for mixing and SM3-based Hash_df for compression.
// Extraction results are fed back into the pool for forward secrecy.
//
// This function may be slow (~3-10ms) due to entropy collection. It uses
// adaptive OSR: if health tests fail, more samples are collected at the
// expense of increased latency, rather than panicking on transient failures.
func Seed() [SeedSize]byte {
	// Collect OS entropy — always succeeds.
	osEntropy := make([]byte, osEntropySize)
	readOSEntropy(osEntropy)

	// Collect jitter entropy with adaptive OSR and health tests.
	jitterSamples := collectWithAdaptiveOSR("jitter", func(s []uint8) error {
		return collectJitterSamples(s, &memory)
	})

	// Collect hash loop noise with adaptive OSR and health tests.
	runtimeSamples := collectWithAdaptiveOSR("hash loop", collectRuntimeSamples)

	// Feed all collected entropy into the pool.
	// Entropy credit uses base numSamples regardless of OSR.
	globalPool.Lock()
	globalPool.pool.add(osEntropy, osEntropyBits)
	globalPool.pool.add(jitterSamples, jitterEntropyBits)
	globalPool.pool.add(runtimeSamples, runtimeEntropyBits)

	// Extract seed via SM3_df compression with forward secrecy feedback.
	seed := globalPool.pool.extract()
	globalPool.Unlock()

	// Clear raw entropy buffers (critical security parameters per
	// GM/T 0105-2021 Section 7.2, Table 1).
	clear(osEntropy)
	clear(jitterSamples)
	clear(runtimeSamples)

	return seed
}
