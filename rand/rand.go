// Package rand provides a cryptographically secure random number generator
// based on SM3 Hash DRBG per GM/T 0105-2021.
//
// It is designed as a drop-in replacement for crypto/rand when GM/T 0105-2021
// compliance is required. The random number generator combines entropy from
// three independent sources (OS, CPU jitter, and runtime noise) with
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

// drbgInstance is the primary DRBG instance, used for low-contention access.
var drbgInstance atomic.Pointer[drbg.HashDrbg]

// selfTestOnce ensures the DRBG known-answer test runs exactly once
// before any random output is produced, per GM/T 0105-2021 Section 5.6.6.
var selfTestOnce sync.Once

// drbgPool provides additional DRBG instances for high-concurrency scenarios.
var drbgPool = sync.Pool{
	New: func() any {
		return newDRBG()
	},
}

// newDRBG creates a new SM3 Hash DRBG instance seeded from the entropy package.
// On first call, it also runs the DRBG self-test (KAT).
//
// The seed is split into entropy input (32 bytes, 256 bits) and nonce
// (16 bytes, 128 bits). Both originate from the entropy pool which combines
// three independent sources, satisfying the GM/T 0105-2021 Appendix B
// requirement that nonce has ≥128 bits of entropy or repeat probability ≤2⁻¹²⁸.
func newDRBG() *drbg.HashDrbg {
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

// getSeed returns a fresh seed for DRBG reseeding.
func getSeed() (entropyInput []byte, nonce []byte) {
	seed := entropy.Seed()
	entropyInput = make([]byte, sm3.Size)
	copy(entropyInput, seed[:sm3.Size])
	nonce = make([]byte, sm3.Size/2)
	copy(nonce, seed[sm3.Size:sm3.Size+sm3.Size/2])

	// Clear seed after extracting components.
	clear(seed[:])

	return entropyInput, nonce
}

func (r *reader) Read(b []byte) (int, error) {
	return Read(b)
}

// Read fills b with cryptographically secure random bytes using an SM3 Hash
// DRBG per GM/T 0105-2021. It never returns an error under normal operation.
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

	// Acquire a DRBG instance from the primary slot or pool.
	d := drbgInstance.Swap(nil)
	if d == nil {
		d = drbgPool.Get().(*drbg.HashDrbg)
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
			entropyInput, _ := getSeed()
			if reseedErr := d.Reseed(entropyInput, additional); reseedErr != nil {
				// Return the DRBG and report the error.
				if !drbgInstance.CompareAndSwap(nil, d) {
					drbgPool.Put(d)
				}
				return total, reseedErr
			}
			// Clear additional input after reseed (per SP 800-90A Section 9.3.1).
			additional = nil
			continue
		} else if err != nil {
			if !drbgInstance.CompareAndSwap(nil, d) {
				drbgPool.Put(d)
			}
			return total, err
		}

		total += len(chunk)
		b = b[len(chunk):]
	}

	// Return the DRBG instance.
	if !drbgInstance.CompareAndSwap(nil, d) {
		drbgPool.Put(d)
	}

	return total, nil
}
