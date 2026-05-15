// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package rand provides a cryptographically secure random number generator
// based on SM3 Hash DRBG per GM/T 0105-2021.
//
// It is designed as a drop-in replacement for crypto/rand when GM/T 0105-2021
// compliance is required. The random number generator combines entropy from
// three independent sources (OS, CPU jitter, and hash loop noise) with
// SM3-based conditioning and SP 800-90B health testing.
//
// Reader and Read are safe for concurrent use.
package rand

import (
	"crypto/rand"
	"io"
	"sync"
	"sync/atomic"

	"github.com/emmansun/gmsm/drbg"
	"github.com/emmansun/gmsm/internal/entropy"
	"github.com/emmansun/gmsm/sm3"
)

const (
	// additionalInputSize is the number of OS random bytes mixed as
	// additional input on each Read call (not counted as entropy).
	additionalInputSize = 16
)

// Reader is a global, shared instance of a cryptographically secure
// random number generator based on SM3 Hash DRBG per GM/T 0105-2021.
// It is safe for concurrent use.
var Reader io.Reader = &reader{}

type reader struct{}

// securityLevel stores the current security level for new DRBG instances.
// Default is SECURITY_LEVEL_TWO (common baseline per GM/T 0105-2021).
var securityLevel atomic.Int32

func init() {
	securityLevel.Store(int32(drbg.SECURITY_LEVEL_TWO))
}

// SetSecurityLevel sets the GM/T 0105-2021 security level for the DRBG.
// This affects newly created DRBG instances (on initialization and reseed).
// Existing instances in the pool are not affected until they are replaced.
//
// The default is [drbg.SECURITY_LEVEL_TWO] (counter interval 2¹⁰, time
// interval 60s). Use [drbg.SECURITY_LEVEL_ONE] for less frequent reseeding
// (counter interval 2²⁰, time interval 600s).
//
// This function should be called before the first Read, typically in an
// init function. It is safe for concurrent use.
func SetSecurityLevel(level drbg.SecurityLevel) {
	securityLevel.Store(int32(level))
}

// drbgInstance is the primary DRBG instance for low-contention access.
// It stores *drbg.HashDrbg (GM mode) using the nil-sentinel atomic swap pattern.
// All DRBG operations in Read() use the drbg.DRBG interface for
// implementation independence; the concrete type surfaces only when
// interacting with the atomic and pool storage.
var drbgInstance atomic.Pointer[drbg.HashDrbg]

// selfTestOnce ensures the DRBG known-answer test runs exactly once
// before any random output is produced, per GM/T 0105-2021 Section 5.6.6.
var selfTestOnce sync.Once

// drbgPool provides additional DRBG instances for high-concurrency scenarios.
// It stores drbg.DRBG interface values; the concrete type is always *drbg.HashDrbg
// (GM mode, created by newDRBG). Type assertions in Read() are safe because
// pool entries are only created by newDRBG() and never replaced with other types.
var drbgPool = sync.Pool{
	New: func() any {
		return newDRBG()
	},
}

// newDRBG creates a new GM-mode SM3 Hash DRBG instance seeded from the entropy
// package and returns it as the drbg.DRBG interface. The returned value is
// always a *drbg.HashDrbg; the interface allows Read() to operate without
// coupling to the concrete implementation type.
//
// The seed is split into entropy input (32 bytes, 256 bits) and nonce
// (16 bytes, 128 bits) per GM/T 0105-2021 Appendix B.3 (nonce ≥128 bits of
// entropy or repeat probability ≤2⁻¹²⁸).
//
// On first call, the DRBG known-answer test (KAT) per Section 5.6.6 is run.
func newDRBG() drbg.DRBG {
	selfTestOnce.Do(selfTest)
	seed := entropy.Seed()

	// Split the seed: entropy (32 bytes) + nonce (16 bytes).
	entropyInput := make([]byte, sm3.Size)
	nonce := make([]byte, sm3.Size/2)
	copy(entropyInput, seed[:sm3.Size])
	copy(nonce, seed[sm3.Size:sm3.Size+sm3.Size/2])

	// Clear seed (critical security parameter per GM/T 0105-2021 Section 7.2).
	clear(seed[:])

	hd, err := drbg.NewGMHashDrbg(drbg.SecurityLevel(securityLevel.Load()), entropyInput, nonce, nil)

	// Clear entropy input and nonce after DRBG instantiation.
	clear(entropyInput)
	clear(nonce)

	if err != nil {
		panic("rand: failed to create DRBG: " + err.Error())
	}
	return hd
}

// getReseedEntropy returns only the entropy input for DRBG reseeding.
// GM/T 0105-2021 reseed (Section 9.2) uses entropy || V || additional
// as seed material — no nonce is required, unlike instantiation.
func getReseedEntropy() []byte {
	seed := entropy.Seed()
	entropyInput := make([]byte, sm3.Size)
	copy(entropyInput, seed[:sm3.Size])
	clear(seed[:])
	return entropyInput
}

func (r *reader) Read(b []byte) (int, error) {
	return Read(b)
}

// Read fills b with cryptographically secure random bytes using an SM3 Hash
// DRBG per GM/T 0105-2021. It always returns len(b), nil.
//
// If the DRBG encounters an unrecoverable error (reseed failure or generate
// failure), Read panics rather than returning degraded output. This matches
// Go 1.24+ crypto/rand.Read semantics and GM/T 0105-2021's requirement that
// the RNG must stop output on failure.
//
// Each call mixes additional OS random bytes into the DRBG output for
// defense-in-depth (per SP 800-90A Section 8.7.2).
func Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Mix OS random bytes as additional input (not counted as entropy).
	additional := make([]byte, additionalInputSize)
	rand.Read(additional)

	// Acquire a DRBG instance.
	// drbgInstance stores *drbg.HashDrbg for the nil-sentinel atomic swap
	// pattern. All DRBG operations below use the drbg.DRBG interface.
	var d drbg.DRBG
	if raw := drbgInstance.Swap(nil); raw != nil {
		d = raw
	} else {
		d = drbgPool.Get().(drbg.DRBG)
	}

	total := 0
	maxPerRequest := d.MaxBytesPerRequest()

	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPerRequest {
			chunk = b[:maxPerRequest]
		}

		err := d.Generate(chunk, additional)
		if err == drbg.ErrReseedRequired {
			// Reseed with fresh entropy from all sources.
			// GM/T 0105-2021 reseed does not require a nonce; only entropy is fed.
			entropyInput := getReseedEntropy()
			if reseedErr := d.Reseed(entropyInput, additional); reseedErr != nil {
				// Destroy the faulty instance — do not return it to the pool.
				d.Destroy()
				panic("rand: DRBG reseed failed: " + reseedErr.Error())
			}
			// Clear additional input after reseed (per SP 800-90A Section 9.3.1).
			additional = nil
			continue
		} else if err != nil {
			// Destroy the faulty instance — do not return it to the pool.
			d.Destroy()
			panic("rand: DRBG generate failed: " + err.Error())
		}

		total += len(chunk)
		b = b[len(chunk):]
	}

	// Return the DRBG instance to the primary slot or pool.
	// Type-assert back to *drbg.HashDrbg: safe because pool and newDRBG()
	// always create *drbg.HashDrbg instances and no other type is stored.
	if concrete, ok := d.(*drbg.HashDrbg); ok {
		if !drbgInstance.CompareAndSwap(nil, concrete) {
			drbgPool.Put(concrete)
		}
	}

	return total, nil
}
