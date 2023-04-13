package drbg

import (
	"encoding/binary"
	"errors"
	"hash"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

const HASH_DRBG_SEED_SIZE = 55
const HASH_DRBG_MAX_SEED_SIZE = 111

// HashDrbg hash DRBG structure, its instance is NOT goroutine safe!!!
type HashDrbg struct {
	BaseDrbg
	newHash func() hash.Hash
	c       []byte
	hashSize int
}

// NewHashDrbg create one hash DRBG instance
func NewHashDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	hd := &HashDrbg{}

	hd.gm = gm
	hd.newHash = newHash
	hd.setSecurityLevel(securityLevel)

	md := newHash()
	hd.hashSize = md.Size()

	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || (hd.gm && len(entropy) < hd.hashSize) || len(entropy) >= MAX_BYTES {
		return nil, errors.New("invalid entropy length")
	}

	// here for the min length, we just check <=0 now
	if len(nonce) == 0 || (hd.gm && len(nonce) < hd.hashSize/2) || len(nonce) >= MAX_BYTES>>1 {
		return nil, errors.New("invalid nonce length")
	}

	if len(personalization) >= MAX_BYTES {
		return nil, errors.New("personalization is too long")
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

// NewNISTHashDrbg return hash DRBG implementation which follows NIST standard
func NewNISTHashDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbg(newHash, securityLevel, false, entropy, nonce, personalization)
}

// NewGMHashDrbg return hash DRBG implementation which follows GM/T 0105-2021 standard
func NewGMHashDrbg(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	return NewHashDrbg(sm3.New, securityLevel, true, entropy, nonce, personalization)
}

// Reseed hash DRBG reseed process. GM/T 0105-2021 has a little different with NIST.
func (hd *HashDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || (hd.gm && len(entropy) < hd.hashSize) || len(entropy) >= MAX_BYTES {
		return errors.New("invalid entropy length")
	}

	if len(additional) >= MAX_BYTES {
		return errors.New("additional input too long")
	}
	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1
	if hd.gm { // seed_material = 0x01 || entropy_input || V || additional_input
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

	// C = Hash_df(0x01 || V, seed_length)
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
	binary.BigEndian.PutUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func (hd *HashDrbg) MaxBytesPerRequest() int {
	if hd.gm {
		return hd.hashSize
	}
	return MAX_BYTES_PER_GENERATE
}

// Generate hash DRBG pseudorandom bits process. GM/T 0105-2021 has a little different with NIST.
// GM/T 0105-2021 can only generate no more than hash.Size bytes once.
func (hd *HashDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	if (hd.gm && len(b) > hd.hashSize) || (!hd.gm && len(b) > MAX_BYTES_PER_GENERATE) {
		return errors.New("too many bytes requested")
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
	if hd.gm { // leftmost(Hash(V))
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
	binary.BigEndian.PutUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := 0; i < int(limit); i++ {
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
