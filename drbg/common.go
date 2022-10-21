package drbg

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"hash"
	"io"
	"time"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

const DRBG_RESEED_COUNTER_INTERVAL_LEVEL_TEST uint64 = 8
const DRBG_RESEED_COUNTER_INTERVAL_LEVEL2 uint64 = 1 << 10
const DRBG_RESEED_COUNTER_INTERVAL_LEVEL1 uint64 = 1 << 20

const DRBG_RESEED_TIME_INTERVAL_LEVEL_TEST = time.Duration(6) * time.Second
const DRBG_RESEED_TIME_INTERVAL_LEVEL2 = time.Duration(60) * time.Second
const DRBG_RESEED_TIME_INTERVAL_LEVEL1 = time.Duration(600) * time.Second

const MAX_BYTES = 1 << 27
const MAX_BYTES_PER_GENERATE = 1 << 11

var ErrReseedRequired = errors.New("reseed reuqired")

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
	if gm && securityStrength < 32 {
		return nil, errors.New("invalid security strength")
	}

	// Get entropy input
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Get nonce
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	prng.impl, err = NewCtrDrbg(cipherProvider, keyLen, securityLevel, gm, entropyInput, nonce, personalization)
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
func NewHashDrbgPrng(md hash.Hash, entropySource io.Reader, securityStrength int, gm bool, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	prng := new(DrbgPrng)
	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}
	prng.securityStrength = selectSecurityStrength(securityStrength)
	if gm && securityStrength < 32 {
		return nil, errors.New("invalid security strength")
	}

	// Get entropy input
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Get nonce from entropy source here
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	prng.impl, err = NewHashDrbg(md, securityLevel, gm, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

// NewNistHashDrbgPrng create pseudo random number generator base on hash DRBG which follows NIST standard
func NewNistHashDrbgPrng(md hash.Hash, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewHashDrbgPrng(md, entropySource, securityStrength, false, securityLevel, personalization)
}

// NewGmHashDrbgPrng create pseudo random number generator base on hash DRBG which follows GM/T 0105-2021 standard
func NewGmHashDrbgPrng(entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	return NewHashDrbgPrng(sm3.New(), entropySource, securityStrength, true, securityLevel, personalization)
}

func (prng *DrbgPrng) getEntropy(entropyInput []byte) error {
	n, err := prng.entropySource.Read(entropyInput)
	if err != nil {
		return err
	}
	if n != len(entropyInput) {
		return errors.New("fail to read enough entropy input")
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
		}
		total += len(b)
		data = data[len(b):]
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
}

type BaseDrbg struct {
	v                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	gm                      bool
}

func (hd *BaseDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter) || (hd.gm && time.Since(hd.reseedTime) > hd.reseedIntervalInTime)
}

func (hd *BaseDrbg) setSecurityLevel(securityLevel SecurityLevel) {
	hd.securityLevel = securityLevel
	switch securityLevel {
	case SECURITY_LEVEL_TWO:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL2
		hd.reseedIntervalInTime = DRBG_RESEED_TIME_INTERVAL_LEVEL2
	case SECURITY_LEVEL_TEST:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL_TEST
		hd.reseedIntervalInTime = DRBG_RESEED_TIME_INTERVAL_LEVEL_TEST
	default:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL1
		hd.reseedIntervalInTime = DRBG_RESEED_TIME_INTERVAL_LEVEL1
	}
}

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
