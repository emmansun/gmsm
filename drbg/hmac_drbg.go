package drbg

import (
	"crypto/hmac"
	"errors"
	"hash"
	"time"
)

// HmacDrbg hmac DRBG structure, its instance is NOT goroutine safe!!!
// The instance should be used in one goroutine only.
// Thera are NO hmac DRBR definition in GM/T 0105-2021 yet.
type HmacDrbg struct {
	BaseDrbg
	newHash  func() hash.Hash
	key      []byte
	hashSize int
}

// NewHmacDrbg create one hmac DRBG instance
func NewHmacDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*HmacDrbg, error) {
	hd := &HmacDrbg{}

	hd.gm = gm
	hd.newHash = newHash
	hd.setSecurityLevel(securityLevel)

	md := newHash()
	hd.hashSize = md.Size()

	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || len(entropy) >= maxBytes {
		return nil, errors.New("drbg: invalid entropy length")
	}

	// here for the min length, we just check <=0 now
	if len(nonce) == 0 || len(nonce) >= maxBytes>>1 {
		return nil, errors.New("drbg: invalid nonce length")
	}

	if len(personalization) >= maxBytes {
		return nil, errors.New("drbg: personalization is too long")
	}

	// HMAC_DRBG_Instantiate_process
	hd.key = make([]byte, hd.hashSize)
	hd.v = make([]byte, hd.hashSize)
	for i := range hd.hashSize {
		hd.key[i] = 0x00
		hd.v[i] = 0x01
	}
	hd.update(entropy, nonce, personalization)
	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

// NewNISTHmacDrbg return hmac DRBG implementation which follows NIST standard
func NewNISTHmacDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HmacDrbg, error) {
	return NewHmacDrbg(newHash, securityLevel, false, entropy, nonce, personalization)
}

// Generate generates pseudo random bytes usging HMAC_DRBG_Generate_process
func (hd *HmacDrbg) Generate(output, additional []byte) error {
	// Step 1. If reseed_counter > reseed_interval, then return [ErrReseedRequired] that a reseed is required
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	// Step 2. If additional_input is provided, then do update
	if len(additional) > 0 {
		hd.update(additional)
	}
	requestedBytes := len(output)
	md := hmac.New(hd.newHash, hd.key)
	for ; requestedBytes > 0; requestedBytes -= hd.hashSize {
		// 4.1. V = HMAC (Key, V)
		md.Reset()
		md.Write(hd.v)
		hd.v = md.Sum(hd.v[:0])
		// 4.2. copy V to output
		copy(output, hd.v)
		if requestedBytes > hd.hashSize {
			output = output[hd.hashSize:]
		}
	}
	// Step 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V)
	hd.update(additional)
	// Step 7. reseed_counter = reseed_counter + 1
	hd.reseedCounter++
	return nil
}

// Reseed hash DRBG reseed process. GM/T 0105-2021 has a little different with NIST.
// reference to NIST.SP.800-90Ar1.pdf section 10.1.2.4
func (hd *HmacDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || (hd.gm && len(entropy) < hd.hashSize) || len(entropy) >= maxBytes {
		return errors.New("drbg: invalid entropy length")
	}

	if len(additional) >= maxBytes {
		return errors.New("drbg: additional input too long")
	}
	hd.update(entropy, additional)
	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *HmacDrbg) MaxBytesPerRequest() int {
	return maxBytesPerGenerate
}

// The HMAC_DRBG_Update function updates the internal state of
// HMAC_DRBG using the provided_data. Note that for this DRBG mechanism, the
// HMAC_DRBG_Update function also serves as a derivation function for the
// instantiate and reseed functions.
func (hd *HmacDrbg) update(byteSlices ...[]byte) error {
	// step 1. K = HMAC(K, V || 0x00 || provided_data)
	md := hmac.New(hd.newHash, hd.key)
	md.Write(hd.v)
	md.Write([]byte{0x00})
	length := 0
	for _, bytes := range byteSlices {
		length += len(bytes)
		if len(bytes) > 0 {
			md.Write(bytes)
		}
	}
	hd.key = md.Sum(hd.key[:0])
	// step 2. V = HMAC(K, V)
	md = hmac.New(hd.newHash, hd.key)
	md.Write(hd.v)
	hd.v = md.Sum(hd.v[:0])
	// step 3. If provided_data = null, then return
	if length == 0 {
		return nil
	}
	// step 4. K = HMAC(K, V || 0x01 || provided_data)
	md.Reset()
	md.Write(hd.v)
	md.Write([]byte{0x01})
	for _, bytes := range byteSlices {
		if len(bytes) > 0 {
			md.Write(bytes)
		}
	}
	hd.key = md.Sum(hd.key[:0])
	// step 5. V = HMAC(K, V)
	md = hmac.New(hd.newHash, hd.key)
	md.Write(hd.v)
	hd.v = md.Sum(hd.v[:0])
	return nil
}

// Destroy destroys the internal state of HMAC DRBG instance
// HMAC的RNG内部状态组成为 {V,Key, reseed_counter, last_reseed_time,reseed_interval_in_counter, reseed_interval_in_time}
func (hd *HmacDrbg) Destroy() {
	hd.BaseDrbg.Destroy()
	setZero(hd.key)
}
