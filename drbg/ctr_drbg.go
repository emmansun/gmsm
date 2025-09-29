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

// NewCtrDrbg create one CTR DRBG instance
func NewCtrDrbg(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, gm bool, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	hd := &CtrDrbg{}

	hd.gm = gm
	hd.setSecurityLevel(securityLevel)

	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || (hd.gm && len(entropy) < 32) || len(entropy) >= maxBytes {
		return nil, errors.New("drbg: invalid entropy length")
	}

	// here for the min length, we just check <=0 now
	if len(nonce) == 0 || (hd.gm && len(nonce) < 16) || len(nonce) >= maxBytes>>1 {
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
	seedMaterial = hd.derive(seedMaterial, hd.seedLength)
	// CTR_DRBG_Updae(seed_material, Key, V)
	hd.update(seedMaterial)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return hd, nil
}

// NewNISTCtrDrbg create one CTR DRBG implementation which follows NIST standard
func NewNISTCtrDrbg(cipherProvider func(key []byte) (cipher.Block, error), keyLen int, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	return NewCtrDrbg(cipherProvider, keyLen, securityLevel, false, entropy, nonce, personalization)
}

// NewGMCtrDrbg create one CTR DRBG implementation which follows GM/T 0105-2021 standard
func NewGMCtrDrbg(securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*CtrDrbg, error) {
	return NewCtrDrbg(sm4.NewCipher, 16, securityLevel, true, entropy, nonce, personalization)
}

func (cd *CtrDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || (cd.gm && len(entropy) < 32) || len(entropy) >= maxBytes {
		return errors.New("drbg: invalid entropy length")
	}

	if len(additional) >= maxBytes {
		return errors.New("drbg: additional input too long")
	}

	// seed_material = entropy_input || additional_input
	var seedMaterial []byte
	if len(additional) == 0 {
		seedMaterial = entropy
	} else {
		seedMaterial = make([]byte, len(entropy)+len(additional))
		copy(seedMaterial, entropy)
		copy(seedMaterial[len(entropy):], additional)
	}
	// seed_material = Block_Cipher_df(seed_material, seed_length)
	seedMaterial = cd.derive(seedMaterial, cd.seedLength)
	// CTR_DRBG_Updae(seed_material, Key, V)
	cd.update(seedMaterial)

	cd.reseedCounter = 1
	cd.reseedTime = time.Now()
	return nil
}

func (cd *CtrDrbg) newBlockCipher(key []byte) cipher.Block {
	block, err := cd.cipherProvider(key)
	if err != nil {
		panic(err)
	}
	return block
}

func (cd *CtrDrbg) MaxBytesPerRequest() int {
	if cd.gm {
		return len(cd.v)
	}
	return maxBytesPerGenerate
}

// Generate CTR DRBG pseudorandom bits generate process.
func (cd *CtrDrbg) Generate(out, additional []byte) error {
	if cd.NeedReseed() {
		return ErrReseedRequired
	}
	outlen := len(cd.v)
	if (cd.gm && len(out) > outlen) || (!cd.gm && len(out) > maxBytesPerGenerate) {
		return errors.New("drbg: too many bytes requested")
	}

	// If len(additional_input) > 0, then
	// additional_input = Block_Cipher_df(additional_input, seed_length)
	// CTR_DRBG_Update(additional_input, Key, V)
	if len(additional) > 0 {
		additional = cd.derive(additional, cd.seedLength)
		cd.update(additional)
	}

	block := cd.newBlockCipher(cd.key)
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
	cd.update(additional)
	cd.reseedCounter++
	return nil
}

func (cd *CtrDrbg) update(seedMaterial []byte) {
	temp := make([]byte, cd.seedLength)
	block := cd.newBlockCipher(cd.key)

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
}

// derive Block_Cipher_df
func (cd *CtrDrbg) derive(seedMaterial []byte, returnBytes int) []byte {
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
	block := cd.newBlockCipher(key)

	for i := 0; i < blocks; i++ {
		byteorder.BEPutUint32(S, uint32(i))
		copy(temp[i*outlen:], cd.bcc(block, S))
	}

	key = temp[:cd.keyLen]
	X := temp[cd.keyLen:cd.seedLength]
	temp = make([]byte, returnBytes)
	block = cd.newBlockCipher(key)
	for i := 0; i < (returnBytes+outlen-1)/outlen; i++ {
		block.Encrypt(X, X)
		copy(temp[i*outlen:], X)
	}
	return temp
}

func (cd *CtrDrbg) bcc(block cipher.Block, data []byte) []byte {
	chainingValue := make([]byte, block.BlockSize())
	for i := 0; i < len(data)/block.BlockSize(); i++ {
		subtle.XORBytes(chainingValue, chainingValue, data[i*block.BlockSize():])
		block.Encrypt(chainingValue, chainingValue)
	}
	return chainingValue
}

// Destroy destroys the internal state of HMAC DRBG instance
// 对称加密的RNG内部状态组成为 {V,Key, reseed_counter, last_reseed_time,reseed_interval_in_counter, reseed_interval_in_time}
func (cd *CtrDrbg) Destroy() {
	cd.BaseDrbg.Destroy()
	setZero(cd.key)
}
