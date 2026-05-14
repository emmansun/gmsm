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
	osEntropySize  = 32   // bytes from OS source
	numSamples     = 1024 // samples per non-OS source
	maxSeedRetries = 100  // max retries before panic

	// Conservative entropy estimates (bits) per source.
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
	// Runtime noise source: 1 bit per sample. Similar conservative
	// estimate. Scheduler jitter and allocation timing depend on system
	// load and Go runtime internals. On idle single-core systems, entropy
	// per sample may be lower than on busy multi-core systems.
	osEntropyBits      = osEntropySize * 8 // 256 bits
	jitterEntropyBits  = numSamples        // 1024 bits
	runtimeEntropyBits = numSamples        // 1024 bits
)

// globalPool is the persistent entropy pool per GM/T 0105-2021 Section 5.3.
// It accumulates entropy across Seed() calls and provides forward secrecy
// by feeding extraction results back into the pool.
var globalPool struct {
	sync.Mutex
	pool entropyPool
}

// Seed collects entropy from three independent sources (OS randomness,
// CPU jitter, and runtime noise), feeds them into the entropy pool,
// runs SP 800-90B health tests on the non-OS sources, and extracts a
// conditioned seed for DRBG instantiation.
//
// The entropy pool uses a circular shift register (per GM/T 0105-2021
// Appendix A.3) for mixing and SM3-based Hash_df for compression.
// Extraction results are fed back into the pool for forward secrecy.
//
// This function may be slow (~1ms) due to entropy collection.
func Seed() [SeedSize]byte {
	// Collect OS entropy — always succeeds.
	osEntropy := make([]byte, osEntropySize)
	readOSEntropy(osEntropy)

	// Collect jitter entropy with health tests and retry on failure.
	jitterSamples := make([]byte, numSamples)
	var retries int
	for {
		err := collectJitterSamples(jitterSamples, &memory)
		if err == nil {
			break
		}
		retries++
		if retries > maxSeedRetries {
			panic("entropy: failed to collect jitter entropy after maximum retries")
		}
	}

	// Collect runtime noise with health tests and retry on failure.
	runtimeSamples := make([]byte, numSamples)
	retries = 0
	for {
		err := collectRuntimeSamples(runtimeSamples)
		if err == nil {
			break
		}
		retries++
		if retries > maxSeedRetries {
			panic("entropy: failed to collect runtime entropy after maximum retries")
		}
	}

	// Feed all collected entropy into the pool.
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
