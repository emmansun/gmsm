package drbg

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"time"
)

const HASH_DRBG_SEED_SIZE = 55
const HASH_DRBG_MAX_SEED_SIZE = 111
const HASH_DRBG_RESEED_COUNTER_INTERVAL_LEVEL2 uint64 = 1 << 10
const HASH_DRBG_RESEED_COUNTER_INTERVAL_LEVEL1 uint64 = 1 << 20
const HASH_DRBG_RESEED_TIME_INTERVAL_LEVEL2 = time.Duration(60) * time.Second
const HASH_DRBG_RESEED_TIME_INTERVAL_LEVEL1 = time.Duration(600) * time.Second
const MAX_BYTES = 1 << 27
const MAX_BYTES_PER_GENERATE = 1 << 11

type SecurityLevel byte

const (
	SECURITY_LEVEL_ONE SecurityLevel = 0x01
	SECURITY_LEVEL_TWO SecurityLevel = 0x02
)

type HashDrbg struct {
	md                      hash.Hash
	v                       []byte
	c                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	gm                      bool
}

// NewHashDrbg create one hash DRBG instance
func NewHashDrbg(md hash.Hash, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	hd := &HashDrbg{}

	hd.gm = gm
	hd.securityLevel = securityLevel
	hd.reseedIntervalInCounter = HASH_DRBG_RESEED_COUNTER_INTERVAL_LEVEL1
	hd.reseedIntervalInTime = HASH_DRBG_RESEED_TIME_INTERVAL_LEVEL1
	if hd.securityLevel == SECURITY_LEVEL_TWO {
		hd.reseedIntervalInCounter = HASH_DRBG_RESEED_COUNTER_INTERVAL_LEVEL2
		hd.reseedIntervalInTime = HASH_DRBG_RESEED_TIME_INTERVAL_LEVEL2
	}

	// here for the min length, we just check <=0 now
	if len(entropy) <= 0 || len(entropy) >= MAX_BYTES {
		return nil, errors.New("invalid entropy length")
	}

	// here for the min length, we just check <=0 now
	if len(nonce) <= 0 || len(nonce) >= MAX_BYTES>>1 {
		return nil, errors.New("invalid nonce length")
	}

	if len(personalization) >= MAX_BYTES {
		return nil, errors.New("personalization is too long")
	}

	hd.md = md
	if md.Size() <= sha256.Size {
		hd.v = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.seedLength = HASH_DRBG_SEED_SIZE
	} else {
		hd.v = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.seedLength = HASH_DRBG_MAX_SEED_SIZE
	}
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)
	seed := hd.derive(seedMaterial, hd.seedLength)
	copy(hd.v, seed)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)
	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

// NewNISTHashDrbg return hash DRBG implementation which follow NIST standard
func NewNISTHashDrbg(md hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbg(md, securityLevel, false, entropy, nonce, personalization)
}

// NewGMHashDrbg return hash DRBG implementation which follow GM/T 0105-2021 standard
func NewGMHashDrbg(md hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbg(md, securityLevel, true, entropy, nonce, personalization)
}

// Reseed hash DRBG reseed process. GM/T 0105-2021 has a little different with NIST.
func (hd *HashDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) <= 0 || len(entropy) >= MAX_BYTES {
		return errors.New("invalid entropy length")
	}

	if len(additional) >= MAX_BYTES {
		return errors.New("additional input too long")
	}
	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1

	if hd.gm { // entropy_input || V || additional_input
		copy(seedMaterial[1:], entropy)
		copy(seedMaterial[len(entropy)+1:], hd.v)
	} else { // V || entropy_input || additional_input
		copy(seedMaterial[1:], hd.v)
		copy(seedMaterial[hd.seedLength+1:], entropy)
	}

	copy(seedMaterial[len(entropy)+hd.seedLength+1:], additional)
	seed := hd.derive(seedMaterial, hd.seedLength)
	copy(hd.v, seed)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)
	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *HashDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter) || (hd.gm && time.Since(hd.reseedTime) > hd.reseedIntervalInTime)
}

func add(left, right []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(left[i]) + uint16(right[i])
		right[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func (hd *HashDrbg) addW(w []byte) {
	t := make([]byte, hd.seedLength)
	copy(t[hd.seedLength-len(w):], w)
	add(t, hd.v, hd.seedLength)
}

func (hd *HashDrbg) addC() {
	add(hd.c, hd.v, hd.seedLength)
}

func (hd *HashDrbg) addH() {
	hd.md.Write([]byte{0x03})
	hd.md.Write(hd.v)
	hd.addW(hd.md.Sum(nil))
	hd.md.Reset()
}

func (hd *HashDrbg) addReseedCounter() {
	t := make([]byte, hd.seedLength)
	binary.BigEndian.PutUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func (hd *HashDrbg) addOne(data []byte) {
	var temp uint16 = 1
	for i := hd.seedLength - 1; i >= 0; i-- {
		temp += uint16(data[i])
		data[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

// Generate hash DRBG generate process. GM/T 0105-2021 has a little different with NIST.
// GM/T 0105-2021 can only generate no more than hash.Size bytes once.
func (hd *HashDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return errors.New("reseed reuqired")
	}
	if (hd.gm && len(b) > hd.md.Size()) || (!hd.gm && len(b) > MAX_BYTES_PER_GENERATE) {
		return errors.New("too many bytes requested")
	}
	md := hd.md
	m := len(b)
	if len(additional) > 0 {
		md.Write([]byte{0x02})
		md.Write(hd.v)
		md.Write(additional)
		w := md.Sum(nil)
		md.Reset()
		hd.addW(w)
	}
	if hd.gm { // leftmost(HASH(V))
		md.Write(hd.v)
		copy(b, md.Sum(nil))
		md.Reset()
	} else {
		limit := uint64(m+md.Size()-1) / uint64(md.Size())
		data := make([]byte, hd.seedLength)
		copy(data, hd.v)
		for i := 0; i < int(limit); i++ {
			md.Write(data)
			copy(b[i*md.Size():], md.Sum(nil))
			hd.addOne(data)
			md.Reset()
		}
	}
	hd.addH()
	hd.addC()
	hd.addReseedCounter()

	hd.reseedCounter++
	return nil
}

func (hd *HashDrbg) derive(seedMaternial []byte, len int) []byte {
	md := hd.md
	limit := uint64(len+md.Size()-1) / uint64(md.Size())
	var requireBytes [4]byte
	binary.BigEndian.PutUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := 0; i < int(limit); i++ {
		md.Write([]byte{ct})
		md.Write(requireBytes[:])
		md.Write(seedMaternial)
		copy(k[i*md.Size():], md.Sum(nil))
		ct++
		md.Reset()
	}
	return k
}
