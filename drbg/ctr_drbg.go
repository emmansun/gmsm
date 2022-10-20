package drbg

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"time"

	"github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/sm4"
)

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
	hd.securityLevel = securityLevel
	hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL1
	hd.reseedIntervalInTime = DRBG_RESEED_TIME_INTERVAL_LEVEL1
	if hd.securityLevel == SECURITY_LEVEL_TWO {
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL2
		hd.reseedIntervalInTime = DRBG_RESEED_TIME_INTERVAL_LEVEL2
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

	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)
	seed := hd.derive(seedMaterial, hd.seedLength)
	hd.update(seed)
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

func (hd *CtrDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) <= 0 || len(entropy) >= MAX_BYTES {
		return errors.New("invalid entropy length")
	}

	if len(additional) >= MAX_BYTES {
		return errors.New("additional input too long")
	}

	var seedMaterial []byte
	if len(additional) == 0 {
		seedMaterial = entropy
	} else {
		seedMaterial = make([]byte, len(entropy)+len(additional))
		copy(seedMaterial, entropy)
		copy(seedMaterial[len(entropy):], additional)
	}
	seed := hd.derive(seedMaterial, hd.seedLength)
	hd.update(seed)
	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *CtrDrbg) newBlockCipher(key []byte) cipher.Block {
	block, err := hd.cipherProvider(key)
	if err != nil {
		panic(err)
	}
	return block
}

// Generate CTR DRBG generate process.
func (hd *CtrDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return errors.New("reseed reuqired")
	}
	outlen := len(hd.v)
	if (hd.gm && len(b) > outlen) || (!hd.gm && len(b) > MAX_BYTES_PER_GENERATE) {
		return errors.New("too many bytes requested")
	}

	if len(additional) > 0 {
		additional = hd.derive(additional, hd.seedLength)
		hd.update(additional)
	}

	block := hd.newBlockCipher(hd.key)
	temp := make([]byte, outlen)

	m := len(b)
	limit := uint64(m+outlen-1) / uint64(outlen)
	for i := 0; i < int(limit); i++ {
		addOne(hd.v, outlen)
		block.Encrypt(temp, hd.v)
		copy(b[i*outlen:], temp)
	}
	hd.update(additional)
	hd.reseedCounter++
	return nil
}

func (cd *CtrDrbg) update(seedMaterial []byte) {
	temp := make([]byte, cd.seedLength)
	block := cd.newBlockCipher(cd.key)

	outlen := block.BlockSize()
	v := make([]byte, outlen)
	output := make([]byte, outlen)
	copy(v, cd.v)
	for i := 0; i < (cd.seedLength+outlen-1)/outlen; i++ {
		addOne(v, outlen)
		block.Encrypt(output, v)
		copy(temp[i*outlen:], output)
	}
	subtle.XORBytes(temp, temp, seedMaterial)
	copy(cd.key, temp)
	copy(cd.v, temp[cd.keyLen:])
}

func (cd *CtrDrbg) derive(seedMaterial []byte, returnBytes int) []byte {
	outlen := cd.seedLength - cd.keyLen
	lenS := ((4 + 4 + len(seedMaterial) + outlen) / outlen) * outlen
	S := make([]byte, lenS+outlen)

	binary.BigEndian.PutUint32(S[outlen:], uint32(len(seedMaterial)))
	binary.BigEndian.PutUint32(S[outlen+4:], uint32(returnBytes))
	copy(S[outlen+8:], seedMaterial)
	S[outlen+8+len(seedMaterial)] = 0x80

	key := make([]byte, cd.keyLen)
	for i := 0; i < cd.keyLen; i++ {
		key[i] = byte(i)
	}
	blocks := (cd.seedLength + outlen - 1) / outlen
	temp := make([]byte, blocks*outlen)
	block := cd.newBlockCipher(key)

	for i := 0; i < blocks; i++ {
		binary.BigEndian.PutUint32(S, uint32(i))
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
