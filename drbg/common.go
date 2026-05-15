// Package drbg implements Random Number Generation Using Deterministic Random Bit Generators.
package drbg

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

const (
	reseedCounterIntervalLevelTest = uint64(8)
	reseedCounterIntervalLevel2    = 1 << 10
	reseedCounterIntervalLevel1    = 1 << 20

	reseedTimeIntervalLevelTest = time.Duration(6) * time.Second
	reseedTimeIntervalLevel2    = time.Duration(60) * time.Second
	reseedTimeIntervalLevel1    = time.Duration(600) * time.Second

	maxBytes            = 1 << 27
	maxBytesPerGenerate = 1 << 11
)

var ErrReseedRequired = errors.New("drbg: reseed required")

type SecurityLevel byte

const (
	SECURITY_LEVEL_ONE  SecurityLevel = 0x01
	SECURITY_LEVEL_TWO  SecurityLevel = 0x02
	SECURITY_LEVEL_TEST SecurityLevel = 0x99
)

// DrbgPrng sample pseudo random number generator base on DRBG
type DrbgPrng struct {
	entropySource    io.Reader
	securityStrength int
	impl             DRBG
}

// NewCtrDrbgPrng create pseudo random number generator base on CTR DRBG
func NewCtrDrbgPrng(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	prng := new(DrbgPrng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}

	prng.securityStrength = selectSecurityStrength(securityStrength)
	mode := DrbgMode(NISTMode)
	if gm {
		mode = GMMode
	}
	if gm && securityStrength < 32 {
		return nil, errors.New("drbg: invalid security strength")
	}

	// Get entropy input
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Get nonce, reference to NIST SP 800-90A, 8.6.7
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	// initial working state
	prng.impl, err = NewCtrDrbgWithMode(cipherProvider, keyLen, securityLevel, mode, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

// NewNistCtrDrbgPrng create pseudo random number generator base on CTR DRBG which follows NIST standard
func NewNistCtrDrbgPrng(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewCtrDrbgPrng(cipherProvider, keyLen, entropySource, securityStrength, false, securityLevel, personalization)
}

// NewNistCtrDrbgPrng create pseudo random number generator base on CTR DRBG which follows GM/T 0105-2021 standard
func NewGmCtrDrbgPrng(entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewCtrDrbgPrng(sm4.NewCipher, 16, entropySource, securityStrength, true, securityLevel, personalization)
}

// NewHashDrbgPrng create pseudo random number generator base on HASH DRBG
func NewHashDrbgPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	prng := new(DrbgPrng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}
	prng.securityStrength = selectSecurityStrength(securityStrength)
	hashMode := DrbgMode(NISTMode)
	if gm {
		hashMode = GMMode
	}
	if gm && securityStrength < 32 {
		return nil, errors.New("drbg: invalid security strength")
	}

	// Get entropy input
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Get nonce, reference to NIST SP 800-90A, 8.6.7
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	// initial working state
	prng.impl, err = NewHashDrbgWithMode(newHash, securityLevel, hashMode, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

// NewNistHashDrbgPrng create pseudo random number generator base on hash DRBG which follows NIST standard
func NewNistHashDrbgPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewHashDrbgPrng(newHash, entropySource, securityStrength, false, securityLevel, personalization)
}

// NewGmHashDrbgPrng create pseudo random number generator base on hash DRBG which follows GM/T 0105-2021 standard
func NewGmHashDrbgPrng(entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewHashDrbgPrng(sm3.New, entropySource, securityStrength, true, securityLevel, personalization)
}

// NewHmacDrbgPrng create pseudo random number generator base on hash mac DRBG
func NewHmacDrbgPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	if gm {
		return nil, errors.New("drbg: gm mode is not supported for hmac drbg")
	}

	prng := new(DrbgPrng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}
	prng.securityStrength = selectSecurityStrength(securityStrength)

	// Get entropy input
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Get nonce, reference to NIST SP 800-90A, 8.6.7
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	// initial working state
	prng.impl, err = NewHmacDrbg(newHash, securityLevel, gm, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

// NewNistHmacDrbgPrng create pseudo random number generator base on hash mac DRBG which follows NIST standard
func NewNistHmacDrbgPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewHmacDrbgPrng(newHash, entropySource, securityStrength, false, securityLevel, personalization)
}

func (prng *DrbgPrng) getEntropy(entropyInput []byte) error {
	n, err := prng.entropySource.Read(entropyInput)
	if err != nil {
		return err
	}
	if n != len(entropyInput) {
		return errors.New("drbg: fail to read enough entropy input")
	}
	return nil
}

func (prng *DrbgPrng) Read(data []byte) (int, error) {
	maxBytesPerRequest := prng.impl.MaxBytesPerRequest()
	total := 0

	for len(data) > 0 {
		b := data
		if len(data) > maxBytesPerRequest {
			b = data[:maxBytesPerRequest]
		}

		err := prng.impl.Generate(b, nil)
		if err == ErrReseedRequired {
			entropyInput := make([]byte, prng.securityStrength)
			err := prng.getEntropy(entropyInput)
			if err != nil {
				return 0, err
			}
			err = prng.impl.Reseed(entropyInput, nil)
			if err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, err
		} else {
			total += len(b)
			data = data[len(b):]
		}
	}
	return total, nil
}

// DRBG interface for both hash and ctr drbg implementations
type DRBG interface {
	// check internal state, return if reseed required
	NeedReseed() bool
	// reseed process
	Reseed(entropy, additional []byte) error
	// generate requrested bytes to b
	Generate(b, additional []byte) error
	// MaxBytesPerRequest return max bytes per request
	MaxBytesPerRequest() int
	// Destroy internal state
	Destroy()
}

// DrbgMode encapsulates the standard-specific behavior differences between
// GM/T 0105-2021 and NIST SP 800-90A. Implement this interface to add support
// for a new standard without modifying the core DRBG implementations.
type DrbgMode interface {
	// IsGM returns true for GM/T 0105-2021 mode, false for NIST SP 800-90A mode.
	IsGM() bool

	// MinEntropyLen returns the minimum required entropy length in bytes.
	// hashOrBlockSize is the underlying hash digest size or cipher block size.
	// Returns 0 if no additional minimum constraint applies beyond len > 0.
	MinEntropyLen(hashOrBlockSize int) int

	// MinNonceLen returns the minimum required nonce length in bytes.
	// Returns 0 if no additional minimum constraint applies beyond len > 0.
	MinNonceLen(hashOrBlockSize int) int

	// NeedReseedByTime returns true if the time-based reseed condition is met.
	// NIST SP 800-90A does not mandate time-based reseeding; GM/T 0105-2021 does.
	NeedReseedByTime(elapsed, interval time.Duration) bool

	// MaxHashOutputBytes returns the maximum bytes allowed per Generate call
	// for hash/HMAC-based DRBGs.
	// GM/T 0105-2021 limits output to one hash block; NIST allows up to 2^19 bits.
	MaxHashOutputBytes(hashSize int) int

	// MaxCtrOutputBytes returns the maximum bytes allowed per Generate call
	// for counter-based DRBGs.
	MaxCtrOutputBytes(blockSize int) int
}

// GMMode is the DrbgMode implementation for GM/T 0105-2021.
var GMMode DrbgMode = gmMode{}

// NISTMode is the DrbgMode implementation for NIST SP 800-90A.
var NISTMode DrbgMode = nistMode{}

type gmMode struct{}

func (gmMode) IsGM() bool { return true }

func (gmMode) MinEntropyLen(hashOrBlockSize int) int { return hashOrBlockSize }

func (gmMode) MinNonceLen(hashOrBlockSize int) int { return hashOrBlockSize / 2 }

func (gmMode) NeedReseedByTime(elapsed, interval time.Duration) bool { return elapsed > interval }

func (gmMode) MaxHashOutputBytes(hashSize int) int { return hashSize }

func (gmMode) MaxCtrOutputBytes(blockSize int) int { return blockSize }

type nistMode struct{}

func (nistMode) IsGM() bool { return false }

func (nistMode) MinEntropyLen(int) int { return 0 }

func (nistMode) MinNonceLen(int) int { return 0 }

func (nistMode) NeedReseedByTime(time.Duration, time.Duration) bool { return false }

func (nistMode) MaxHashOutputBytes(int) int { return maxBytesPerGenerate }

func (nistMode) MaxCtrOutputBytes(int) int { return maxBytesPerGenerate }

type BaseDrbg struct {
	v                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	mode                    DrbgMode
}

func (hd *BaseDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter) ||
		hd.mode.NeedReseedByTime(time.Since(hd.reseedTime), hd.reseedIntervalInTime)
}

func (hd *BaseDrbg) setSecurityLevel(securityLevel SecurityLevel) {
	hd.securityLevel = securityLevel
	switch securityLevel {
	case SECURITY_LEVEL_TWO:
		hd.reseedIntervalInCounter = reseedCounterIntervalLevel2
		hd.reseedIntervalInTime = reseedTimeIntervalLevel2
	case SECURITY_LEVEL_TEST:
		hd.reseedIntervalInCounter = reseedCounterIntervalLevelTest
		hd.reseedIntervalInTime = reseedTimeIntervalLevelTest
	default:
		hd.reseedIntervalInCounter = reseedCounterIntervalLevel1
		hd.reseedIntervalInTime = reseedTimeIntervalLevel1
	}
}

// Destroy securely clears all internal state data of the DRBG instance.
//
// This method should be called when the DRBG instance is no longer needed to
// ensure sensitive data is removed from memory.
//
// References:
// - GM/T 0105-2021 B.2, E.2: Specifies that internal states must be cleared when no longer needed.
// - NIST SP 800-90A Rev.1: Recommends securely erasing sensitive data to prevent leakage.
func (hd *BaseDrbg) Destroy() {
	setZero(hd.v)
	hd.seedLength = 0
	atomic.StoreUint64(&hd.reseedCounter, 0xFFFFFFFFFFFFFFFF)
	atomic.StoreUint64(&hd.reseedCounter, 0x00)
	atomic.StoreUint64(&hd.reseedIntervalInCounter, 0xFFFFFFFFFFFFFFFF)
	atomic.StoreUint64(&hd.reseedIntervalInCounter, 0x00)
	hd.reseedTime = time.Time{}
	atomic.StoreInt64((*int64)(&hd.reseedIntervalInTime), int64(1<<63-1))
	atomic.StoreInt64((*int64)(&hd.reseedIntervalInTime), int64(0))
}

// Set security_strength to the lowest security strength greater than or equal to
// requested_instantiation_security_strength from the set {112, 128, 192, 256}.
func selectSecurityStrength(requested int) int {
	switch {
	case requested <= 14:
		return 14
	case requested <= 16:
		return 16
	case requested <= 24:
		return 24
	case requested <= 32:
		return 32
	default:
		return requested
	}
}

func add(left, right []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(left[i]) + uint16(right[i])
		right[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func addOne(data []byte, len int) {
	var temp uint16 = 1
	for i := len - 1; i >= 0; i-- {
		temp += uint16(data[i])
		data[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

// setZero securely erases the content of a byte slice by overwriting it multiple times.
// It follows a secure erasure pattern by first writing 0xFF and then 0x00 to each byte
// three times in succession. Memory barriers (via runtime.KeepAlive) are used between
// operations to ensure write completion and prevent compiler optimizations from eliminating
// the seemingly redundant writes.
//
// This function is used to clear sensitive data (like cryptographic keys or passwords)
// from memory to minimize the risk of data exposure in memory dumps or through
// side-channel attacks.
//
// If the provided slice is nil, the function returns immediately without action.
func setZero(data []byte) {
	if data == nil {
		return
	}
	for range 3 {
		for i := range data {
			data[i] = 0xFF
		}
		runtime.KeepAlive(data)

		clear(data)
		// This should keep buf's backing array live and thus prevent dead store
		// elimination, according to discussion at
		// https://github.com/golang/go/issues/33325 .
		runtime.KeepAlive(data)
	}
}
