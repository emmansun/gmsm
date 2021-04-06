package sm4

import (
	"crypto/cipher"

	smcipher "github.com/emmansun/gmsm/cipher"
)

// Assert that sm4CipherAsm implements the ctrAble interface.
var _ ctrAble = (*sm4CipherAsm)(nil)

type ctr struct {
	b       *sm4CipherAsm
	ctr     []byte
	out     []byte
	outUsed int
}

const streamBufferSize = 512

// NewCTR returns a Stream which encrypts/decrypts using the SM4 block
// cipher in counter mode. The length of iv must be the same as BlockSize.
func (c *sm4CipherAsm) NewCTR(iv []byte) cipher.Stream {
	if len(iv) != BlockSize {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < BlockSize {
		bufSize = BlockSize
	}
	s := &ctr{
		b:       c,
		ctr:     make([]byte, 4*len(iv)),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
	copy(s.ctr, iv)
	s.genCtr(BlockSize)
	s.genCtr(2 * BlockSize)
	s.genCtr(3 * BlockSize)
	return s

}

func (x *ctr) genCtr(start int) {
	if start > 0 {
		copy(x.ctr[start:], x.ctr[start-BlockSize:start])
	} else {
		copy(x.ctr[start:], x.ctr[len(x.ctr)-BlockSize:])
	}
	// Increment counter
	end := start + BlockSize
	for i := end - 1; i >= 0; i-- {
		x.ctr[i]++
		if x.ctr[i] != 0 {
			break
		}
	}
}

func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	for remain <= len(x.out)-FourBlocksSize {
		encryptBlocksAsm(&x.b.enc[0], &x.out[remain:][0], &x.ctr[0])
		remain += FourBlocksSize

		// Increment counter
		x.genCtr(0)
		x.genCtr(BlockSize)
		x.genCtr(2 * BlockSize)
		x.genCtr(3 * BlockSize)
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}
	if smcipher.InexactOverlap(dst[:len(src)], src) {
		panic("cipher: invalid buffer overlap")
	}
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-BlockSize {
			x.refill()
		}
		n := smcipher.XorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}
