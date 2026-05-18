package drbg

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/emmansun/gmsm/internal/byteorder"
	"github.com/emmansun/gmsm/sm4"
)

// CtrDrbg CTR DRBG structure, its instance is NOT goroutine safe!!!
type CtrDrbg struct {
	BaseDrbg
	cipherProvider func(key []byte) (cipher.Block, error)
	key            []byte
	keyLen         int
}

// NewCtrDrbgWithMode creates a CTR DRBG instance using the given DrbgMode.
// Use GMMode for GM/T 0105-2021 compliance, NISTMode for NIST SP 800-90A compliance.
func NewCtrDrbgWithMode(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, mode DrbgMode, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	hd := &CtrDrbg{}

	hd.mode = mode
	hd.setSecurityLevel(securityLevel)

	// GM/T 0105-2021 requires entropy ≥ 32 bytes; NIST requires only > 0
	minEntropy := mode.MinEntropyLen(32)
	if len(entropy) == 0 || (minEntropy > 0 && len(entropy) < minEntropy) || len(entropy) >= maxBytes {
		return nil, errors.New("drbg: invalid entropy length")
	}

	// GM/T 0105-2021 requires nonce ≥ 16 bytes; NIST requires only > 0
	minNonce := mode.MinNonceLen(32)
	if len(nonce) == 0 || (minNonce > 0 && len(nonce) < minNonce) || len(nonce) >= maxBytes>>1 {
		return nil, errors.New("drbg: invalid nonce length")
	}

	if len(personalization) >= maxBytes {
		return nil, errors.New("drbg: personalization is too long")
	}

	hd.cipherProvider = cipherProvider
	hd.keyLen = keyLen
	temp := make([]byte, hd.keyLen)
	block, err := cipherProvider(temp)
	if err != nil {
		return nil, err
	}
	hd.seedLength = block.BlockSize() + keyLen
	hd.v = make([]byte, block.BlockSize())
	hd.key = make([]byte, hd.keyLen)

	// seed_material = entropy_input || instantiation_nonce || personalization_string
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)
	// seed_material = Block_Cipher_df(seed_material, seed_length)
	seedMaterial, err = hd.derive(seedMaterial, hd.seedLength)
	if err != nil {
		return nil, err
	}
	// CTR_DRBG_Updae(seed_material, Key, V)
	err = hd.update(seedMaterial)
	if err != nil {
		return nil, err
	}

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return hd, nil
}

// NewNISTCtrDrbg create one CTR DRBG implementation which follows NIST standard
func NewNISTCtrDrbg(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	return NewCtrDrbgWithMode(cipherProvider, keyLen, securityLevel, NISTMode, entropy, nonce, personalization)
}

// NewGMCtrDrbg create one CTR DRBG implementation which follows GM/T 0105-2021 standard
func NewGMCtrDrbg(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	return NewCtrDrbgWithMode(sm4.NewCipher, 16, securityLevel, GMMode, entropy, nonce, personalization)
}

// NewCtrDrbg create one CTR DRBG instance
func NewCtrDrbg(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	mode := DrbgMode(NISTMode)
	if gm {
		mode = GMMode
	}
	return NewCtrDrbgWithMode(cipherProvider, keyLen, securityLevel, mode, entropy, nonce, personalization)
}

func (cd *CtrDrbg) Reseed(entropy, additional []byte) error {
	minEntropy := cd.mode.MinEntropyLen(32)
	if len(entropy) == 0 || (minEntropy > 0 && len(entropy) < minEntropy) || len(entropy) >= maxBytes {
		return errors.New("drbg: invalid entropy length")
	}

	if len(additional) >= maxBytes {
		return errors.New("drbg: additional input too long")
	}

	// seed_material = entropy_input || additional_input
	var seedMaterial []byte
	var err error
	if len(additional) == 0 {
		seedMaterial = entropy
	} else {
		seedMaterial = make([]byte, len(entropy)+len(additional))
		copy(seedMaterial, entropy)
		copy(seedMaterial[len(entropy):], additional)
	}
	// seed_material = Block_Cipher_df(seed_material, seed_length)
	seedMaterial, err = cd.derive(seedMaterial, cd.seedLength)
	if err != nil {
		return err
	}
	// CTR_DRBG_Updae(seed_material, Key, V)
	err = cd.update(seedMaterial)
	if err != nil {
		return err
	}

	cd.reseedCounter = 1
	cd.reseedTime = time.Now()
	return nil
}

func (cd *CtrDrbg) newBlockCipher(key []byte) (cipher.Block, error) {
	block, err := cd.cipherProvider(key)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (cd *CtrDrbg) MaxBytesPerRequest() int {
	return cd.mode.MaxCtrOutputBytes(len(cd.v))
}

// Generate CTR DRBG pseudorandom bits generate process.
func (cd *CtrDrbg) Generate(out, additional []byte) (bool, error) {
	if cd.NeedReseed() {
		return true, nil
	}
	if len(additional) >= maxBytes {
		return false, errors.New("drbg: additional input too long")
	}
	outlen := len(cd.v)
	if len(out) > cd.mode.MaxCtrOutputBytes(outlen) {
		return false, errors.New("drbg: too many bytes requested")
	}

	// If len(additional_input) > 0, then
	// additional_input = Block_Cipher_df(additional_input, seed_length)
	// CTR_DRBG_Update(additional_input, Key, V)
	if len(additional) > 0 {
		var err error
		additional, err = cd.derive(additional, cd.seedLength)
		if err != nil {
			return false, err
		}
		err = cd.update(additional)
		if err != nil {
			return false, err
		}
	}

	block, err := cd.newBlockCipher(cd.key)
	if err != nil {
		return false, err
	}
	temp := make([]byte, outlen)

	m := len(out)
	limit := uint64(m+outlen-1) / uint64(outlen)
	for i := range int(limit) {
		// V = (V + 1) mod 2^outlen)
		addOne(cd.v, outlen)
		// output_block = Encrypt(Key, V)
		block.Encrypt(temp, cd.v)
		copy(out[i*outlen:], temp)
	}
	err = cd.update(additional)
	if err != nil {
		return false, err
	}
	cd.reseedCounter++
	return false, nil
}

func (cd *CtrDrbg) update(seedMaterial []byte) error {
	temp := make([]byte, cd.seedLength)
	block, err := cd.newBlockCipher(cd.key)
	if err != nil {
		return err
	}

	outlen := block.BlockSize()
	v := make([]byte, outlen)
	output := make([]byte, outlen)
	copy(v, cd.v)
	for i := range (cd.seedLength + outlen - 1) / outlen {
		// V = (V + 1) mod 2^outlen
		addOne(v, outlen)
		// output_block = Encrypt(Key, V)
		block.Encrypt(output, v)
		copy(temp[i*outlen:], output)
	}
	// temp = temp XOR seed_material
	subtle.XORBytes(temp, temp, seedMaterial)
	// Key = leftmost(temp, key_length)
	copy(cd.key, temp)
	// V = rightmost(temp, outlen)
	copy(cd.v, temp[cd.keyLen:])
	return nil
}

// derive Block_Cipher_df
func (cd *CtrDrbg) derive(seedMaterial []byte, returnBytes int) ([]byte, error) {
	outlen := cd.seedLength - cd.keyLen
	lenS := ((4 + 4 + len(seedMaterial) + outlen) / outlen) * outlen
	S := make([]byte, lenS+outlen)

	// S = counter || len(seed_material) || len(return_bytes) || seed_material || 0x80
	// len(S) = ((outlen + 4 + 4 + len(seed_material) + 1 + outlen - 1) / outlen) * outlen
	byteorder.BEPutUint32(S[outlen:], uint32(len(seedMaterial)))
	byteorder.BEPutUint32(S[outlen+4:], uint32(returnBytes))
	copy(S[outlen+8:], seedMaterial)
	S[outlen+8+len(seedMaterial)] = 0x80

	key := make([]byte, cd.keyLen)
	for i := range cd.keyLen {
		key[i] = byte(i)
	}
	blocks := (cd.seedLength + outlen - 1) / outlen
	temp := make([]byte, blocks*outlen)
	block, err := cd.newBlockCipher(key)
	if err != nil {
		return nil, err
	}

	for i := 0; i < blocks; i++ {
		byteorder.BEPutUint32(S, uint32(i))
		copy(temp[i*outlen:], cd.bcc(block, S))
	}

	key = temp[:cd.keyLen]
	X := temp[cd.keyLen:cd.seedLength]
	temp = make([]byte, returnBytes)
	block, err = cd.newBlockCipher(key)
	if err != nil {
		return nil, err
	}
	for i := 0; i < (returnBytes+outlen-1)/outlen; i++ {
		block.Encrypt(X, X)
		copy(temp[i*outlen:], X)
	}
	return temp, nil
}

func (cd *CtrDrbg) bcc(block cipher.Block, data []byte) []byte {
	chainingValue := make([]byte, block.BlockSize())
	for i := 0; i < len(data)/block.BlockSize(); i++ {
		subtle.XORBytes(chainingValue, chainingValue, data[i*block.BlockSize():])
		block.Encrypt(chainingValue, chainingValue)
	}
	return chainingValue
}

// Destroy destroys the internal state of DRBG instance
// working_state = {V, Key, reseed_counter, last_reseed_time,reseed_interval_in_counter, reseed_interval_in_time}
func (cd *CtrDrbg) Destroy() {
	cd.BaseDrbg.Destroy()
	zeroize(cd.key)
}
