package drbg

import (
	"errors"
	"hash"
	"time"

	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/sm3"
)

const HASH_DRBG_SEED_SIZE = 55
const HASH_DRBG_MAX_SEED_SIZE = 111

// HashDrbg hash DRBG structure, its instance is NOT goroutine safe!!!
type HashDrbg struct {
	BaseDrbg
	newHash  func() hash.Hash
	c        []byte
	hashSize int
}

// NewHashDrbgWithMode creates a hash DRBG instance using the given DrbgMode.
// Use GMMode for GM/T 0105-2021 compliance, NISTMode for NIST SP 800-90A compliance,
// or provide a custom DrbgMode implementation for other standards.
func NewHashDrbgWithMode(newHash func() hash.Hash, securityLevel SecurityLevel, mode DrbgMode, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	hd := &HashDrbg{}

	hd.mode = mode
	hd.newHash = newHash
	hd.setSecurityLevel(securityLevel)

	md := newHash()
	hd.hashSize = md.Size()

	minEntropy := mode.MinEntropyLen(hd.hashSize)
	if len(entropy) == 0 || (minEntropy > 0 && len(entropy) < minEntropy) || len(entropy) >= maxBytes {
		return nil, errors.New("drbg: invalid entropy length")
	}

	minNonce := mode.MinNonceLen(hd.hashSize)
	if len(nonce) == 0 || (minNonce > 0 && len(nonce) < minNonce) || len(nonce) >= maxBytes>>1 {
		return nil, errors.New("drbg: invalid nonce length")
	}

	if len(personalization) >= maxBytes {
		return nil, errors.New("drbg: personalization is too long")
	}

	if hd.hashSize <= sm3.Size {
		hd.v = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.seedLength = HASH_DRBG_SEED_SIZE
	} else {
		hd.v = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.seedLength = HASH_DRBG_MAX_SEED_SIZE
	}
	// seed_material = entropy_input || instantiation_nonce || personalization_string
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)

	// seed = Hash_df(seed_material, seed_length)
	seed := hd.derive(seedMaterial, hd.seedLength)
	// V = seed
	copy(hd.v, seed)

	// C = Hash_df(0x00 || V, seed_length)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

// NewHashDrbg create one hash DRBG instance
func NewHashDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	mode := DrbgMode(NISTMode)
	if gm {
		mode = GMMode
	}
	return NewHashDrbgWithMode(newHash, securityLevel, mode, entropy, nonce, personalization)
}

// NewNISTHashDrbg return hash DRBG implementation which follows NIST standard
func NewNISTHashDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbgWithMode(newHash, securityLevel, NISTMode, entropy, nonce, personalization)
}

// NewGMHashDrbg return hash DRBG implementation which follows GM/T 0105-2021 standard
func NewGMHashDrbg(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbgWithMode(sm3.New, securityLevel, GMMode, entropy, nonce, personalization)
}

// Reseed hash DRBG reseed process.
//
// GM/T 0105-2021 divergence: seed material ordering differs from NIST SP 800-90A.
// GM/T 0105-2021 Section 9.2: seed_material = 0x01 || entropy || V || additional
// NIST SP 800-90A Section 10.1.1.4: seed_material = 0x01 || V || entropy || additional
func (hd *HashDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	minEntropy := hd.mode.MinEntropyLen(hd.hashSize)
	if len(entropy) == 0 || (minEntropy > 0 && len(entropy) < minEntropy) || len(entropy) >= maxBytes {
		return errors.New("drbg: invalid entropy length")
	}

	if len(additional) >= maxBytes {
		return errors.New("drbg: additional input too long")
	}
	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1
	if hd.mode.IsGM() { // GM/T 0105-2021: seed_material = 0x01 || entropy || V || additional_input
		// Reference: GM/T 0105-2021 Section 9.2, Table 3
		copy(seedMaterial[1:], entropy)
		copy(seedMaterial[len(entropy)+1:], hd.v)
	} else { // seed_material = 0x01 || V || entropy_input || additional_input
		copy(seedMaterial[1:], hd.v)
		copy(seedMaterial[hd.seedLength+1:], entropy)
	}
	copy(seedMaterial[len(entropy)+hd.seedLength+1:], additional)

	// seed = Hash_df(seed_material, seed_length)
	seed := hd.derive(seedMaterial, hd.seedLength)

	// V = seed
	copy(hd.v, seed)
	temp := make([]byte, hd.seedLength+1)

	// C = Hash_df(0x00 || V, seed_length)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.derive(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
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
	md := hd.newHash()
	md.Write([]byte{0x03})
	md.Write(hd.v)
	hd.addW(md.Sum(nil))
}

func (hd *HashDrbg) addReseedCounter() {
	t := make([]byte, hd.seedLength)
	byteorder.BEPutUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func (hd *HashDrbg) MaxBytesPerRequest() int {
	// GM/T 0105-2021 divergence: GM mode limits output to hash.Size (32 bytes for SM3).
	// Reference: GM/T 0105-2021 Section 9.3 — each Generate call produces exactly
	// one hash output block. NIST SP 800-90A Section 10.1.1.4 allows up to 2^19 bits.
	return hd.mode.MaxHashOutputBytes(hd.hashSize)
}

// Generate hash DRBG pseudorandom bits process.
//
// GM/T 0105-2021 divergence: output generation algorithm differs from NIST SP 800-90A.
// GM mode (GM/T 0105-2021 Section 9.3): output = leftmost(Hash(V), requested_bytes);
//
//	maximum output per call = hash.Size (32 bytes for SM3).
//
// NIST mode (SP 800-90A Section 10.1.1.4): output uses a counter-based loop over
//
//	incrementing copies of V; maximum output per call = 2^19 bits (65536 bytes).
func (hd *HashDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	if len(additional) >= maxBytes {
		return errors.New("drbg: additional input too long")
	}
	if len(b) > hd.mode.MaxHashOutputBytes(hd.hashSize) {
		return errors.New("drbg: too many bytes requested")
	}
	md := hd.newHash()
	m := len(b)

	// if len(additional_input) > 0, then
	// w = Hash(0x02 || V || additional_input)
	if len(additional) > 0 {
		md.Write([]byte{0x02})
		md.Write(hd.v)
		md.Write(additional)
		w := md.Sum(nil)
		md.Reset()
		hd.addW(w)
	}
	if hd.mode.IsGM() { // GM/T 0105-2021: output = leftmost(Hash(V), len(b))
		// Reference: GM/T 0105-2021 Section 9.3, Step 4
		md.Write(hd.v)
		copy(b, md.Sum(nil))
		md.Reset()
	} else { // NIST SP 800-90A: counter-based generation loop
		limit := uint64(m+md.Size()-1) / uint64(md.Size())
		data := make([]byte, hd.seedLength)
		copy(data, hd.v)
		for i := range int(limit) {
			md.Write(data)
			copy(b[i*md.Size():], md.Sum(nil))
			addOne(data, hd.seedLength)
			md.Reset()
		}
	}
	// V = (V + H + C + reseed_counter) mode 2^seed_length
	hd.addH()
	hd.addC()
	hd.addReseedCounter()

	hd.reseedCounter++
	return nil
}

// derive Hash_df
func (hd *HashDrbg) derive(seedMaterial []byte, len int) []byte {
	md := hd.newHash()
	limit := uint64(len+hd.hashSize-1) / uint64(hd.hashSize)
	var requireBytes [4]byte
	byteorder.BEPutUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := range int(limit) {
		// Hash( counter_byte || return_bits || seed_material )
		md.Write([]byte{ct})
		md.Write(requireBytes[:])
		md.Write(seedMaterial)
		copy(k[i*md.Size():], md.Sum(nil))
		ct++
		md.Reset()
	}
	return k
}

// Destroy destroys the internal state of DRBG instance
// working_state = {V, C, reseed_counter, last_reseed_time,reseed_interval_in_counter, reseed_interval_in_time}
func (hd *HashDrbg) Destroy() {
	hd.BaseDrbg.Destroy()
	setZero(hd.c)
}
