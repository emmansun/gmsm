// Copyright 2024 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package cbcmac implements the Message Authentication Code with the block chipher mechanisms.
package cbcmac

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/emmansun/gmsm/padding"
)

// Reference: GB/T 15821.1-2020 Security techniques
// Message authentication codes - Part 1: Mechanisms using block ciphers

// BockCipherMAC is the interface that wraps the basic MAC method.
type BockCipherMAC interface {
	// Size returns the MAC value's number of bytes.
	Size() int

	// MAC calculates the MAC of the given data.
	// The MAC value's number of bytes is returned by Size.
	// Intercept message authentication code as needed.
	MAC(src []byte) []byte
}

// cbcmac implements the basic CBC-MAC mode of operation for block ciphers.
type cbcmac struct {
	b    cipher.Block
	pad  padding.Padding
	size int
}

// NewCBCMAC returns a CBC-MAC instance that implements the MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 1
func NewCBCMAC(b cipher.Block, size int) BockCipherMAC {
	return NewCBCMACWithPadding(b, size, padding.NewISO9797M2Padding)
}


// NewCBCMACWithPadding creates a new CBC-MAC (Cipher Block Chaining Message Authentication Code) 
// with the specified block cipher, MAC size, and padding function. The MAC size must be greater 
// than 0 and less than or equal to the block size of the cipher. If the size is invalid, the 
// function will panic. The padding function is used to pad the input to the block size of the cipher.
//
// Parameters:
// - b: The block cipher to use for CBC-MAC.
// - size: The size of the MAC in bytes. Must be greater than 0 and less than or equal to the block size of the cipher.
// - paddingFunc: The padding function to use for padding the input to the block size of the cipher.
//
// Returns:
// - A BockCipherMAC instance that can be used to compute the CBC-MAC.
func NewCBCMACWithPadding(b cipher.Block, size int, paddingFunc padding.PaddingFunc) BockCipherMAC {
	if size <= 0 || size > b.BlockSize() {
		panic("cbcmac: invalid size")
	}
	return &cbcmac{b: b, pad: paddingFunc(uint(b.BlockSize())), size: size}
}

func (c *cbcmac) Size() int {
	return c.size
}

// MAC calculates the MAC of the given data.
// The data is padded with the padding scheme of the block cipher before processing.
func (c *cbcmac) MAC(src []byte) []byte {
	src = c.pad.Pad(src)
	blockSize := c.b.BlockSize()
	tag := make([]byte, blockSize)
	for len(src) > 0 {
		subtle.XORBytes(tag, tag, src[:blockSize])
		c.b.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	return tag[:c.size]
}

// emac implements the EMAC mode of operation for block ciphers.
type emac struct {
	pad    padding.Padding
	b1, b2 cipher.Block
	size   int
}

// NewEMAC returns an EMAC instance that implements MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 2
func NewEMAC(creator func(key []byte) (cipher.Block, error), key1, key2 []byte, size int) BockCipherMAC {
	var b1, b2 cipher.Block
	var err error
	if b1, err = creator(key1); err != nil {
		panic(err)
	}
	if size <= 0 || size > b1.BlockSize() {
		panic("cbcmac: invalid size")
	}
	if b2, err = creator(key2); err != nil {
		panic(err)
	}
	return &emac{pad: padding.NewISO9797M2Padding(uint(b1.BlockSize())), b1: b1, b2: b2, size: size}
}

func (e *emac) Size() int {
	return e.size
}

func (e *emac) MAC(src []byte) []byte {
	src = e.pad.Pad(src)
	blockSize := e.b1.BlockSize()
	tag := make([]byte, blockSize)
	for len(src) > 0 {
		subtle.XORBytes(tag, tag, src[:blockSize])
		e.b1.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	e.b2.Encrypt(tag, tag)
	return tag[:e.size]
}

type ansiRetailMAC emac

// NewANSIRetailMAC returns an ANSI Retail MAC instance that implements MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 3
func NewANSIRetailMAC(creator func(key []byte) (cipher.Block, error), key1, key2 []byte, size int) BockCipherMAC {
	return (*ansiRetailMAC)(NewEMAC(creator, key1, key2, size).(*emac))
}

func (e *ansiRetailMAC) Size() int {
	return e.size
}

func (e *ansiRetailMAC) MAC(src []byte) []byte {
	src = e.pad.Pad(src)
	blockSize := e.b1.BlockSize()
	tag := make([]byte, blockSize)
	for len(src) > 0 {
		subtle.XORBytes(tag, tag, src[:blockSize])
		e.b1.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	e.b2.Decrypt(tag, tag)
	e.b1.Encrypt(tag, tag)
	return tag[:e.size]
}

type macDES struct {
	pad        padding.Padding
	b1, b2, b3 cipher.Block
	size       int
}

// NewMACDES returns a MAC-DES instance that implements MAC with the given block cipher.
// The padding scheme is ISO/IEC 9797-1 method 2.
// GB/T 15821.1-2020 MAC scheme 4
func NewMACDES(creator func(key []byte) (cipher.Block, error), key1, key2 []byte, size int) BockCipherMAC {
	var b1, b2, b3 cipher.Block
	var err error
	if b1, err = creator(key1); err != nil {
		panic(err)
	}
	if size <= 0 || size > b1.BlockSize() {
		panic("cbcmac: invalid size")
	}
	if b2, err = creator(key2); err != nil {
		panic(err)
	}
	key3 := make([]byte, len(key2))
	copy(key3, key2)
	for i := 0; i < len(key3); i++ {
		key3[i] ^= 0xF0
	}
	if b3, err = creator(key3); err != nil {
		panic(err)
	}
	return &macDES{pad: padding.NewISO9797M2Padding(uint(b1.BlockSize())), b1: b1, b2: b2, b3: b3, size: size}
}

func (m *macDES) Size() int {
	return m.size
}

func (m *macDES) MAC(src []byte) []byte {
	src = m.pad.Pad(src)
	blockSize := m.b1.BlockSize()
	tag := make([]byte, blockSize)
	copy(tag, src[:blockSize])
	m.b1.Encrypt(tag, tag)
	m.b3.Encrypt(tag, tag)
	src = src[blockSize:]
	for len(src) > 0 {
		subtle.XORBytes(tag, tag, src[:blockSize])
		m.b1.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	m.b2.Encrypt(tag, tag)
	return tag[:m.size]
}

type cmac struct {
	b         cipher.Block
	k1, k2    []byte
	size      int
	blockSize int
	tag       []byte
	x         []byte
	nx        int
	len       uint64
}

// NewCMAC returns a CMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 5
//
// Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf
func NewCMAC(b cipher.Block, size int) *cmac {
	if size <= 0 || size > b.BlockSize() {
		panic("cbcmac: invalid size")
	}
	blockSize := b.BlockSize()
	k1 := make([]byte, blockSize)
	k2 := make([]byte, blockSize)
	b.Encrypt(k1, k1)
	msb := shiftLeft(k1)
	k1[len(k1)-1] ^= msb * 0b10000111

	copy(k2, k1)
	msb = shiftLeft(k2)
	k2[len(k2)-1] ^= msb * 0b10000111

	d := &cmac{b: b, k1: k1, k2: k2, size: size}
	d.blockSize = blockSize
	d.tag = make([]byte, blockSize)
	d.x = make([]byte, blockSize)
	return d
}

func (c *cmac) Reset() {
	for i := range c.tag {
		c.tag[i] = 0
	}
	c.nx = 0
	c.len = 0
}

func (c *cmac) BlockSize() int {
	return c.blockSize
}

func (c *cmac) Size() int {
	return c.size
}

func (d *cmac) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if nn == 0 {
		// nothing to do
		return
	}
	d.len += uint64(nn)
	if d.nx == d.blockSize {
		// handle remaining full block
		d.block(d.x)
		d.nx = 0
	} else if d.nx > 0 {
		// handle remaining incomplete block
		n := copy(d.x[d.nx:], p)
		d.nx += n
		p = p[n:]
		if len(p) > 0 {
			d.block(d.x)
			d.nx = 0
		}
	}
	lenP := len(p)
	if lenP > d.blockSize {
		n := lenP &^ (d.blockSize - 1)
		if n == lenP {
			n -= d.blockSize
		}
		d.block(p[:n])
		p = p[n:]
	}
	// save remaining partial/full block
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (c *cmac) block(p []byte) {
	for len(p) >= c.blockSize {
		subtle.XORBytes(c.tag, p[:c.blockSize], c.tag)
		c.b.Encrypt(c.tag, c.tag)
		p = p[c.blockSize:]
	}
}

// Sum appends the current hash to in and returns the resulting slice.
// It does not change the underlying hash state.
func (d *cmac) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	// shared block cipher and k1, k2, x
	d0 := *d
	// use slices.Clone() later
	d0.tag = make([]byte, d.blockSize)
	copy(d0.tag, d.tag)
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (c *cmac) checkSum() []byte {
	tag := make([]byte, c.size)
	if c.nx == 0 {
		// Special-cased as a single empty partial final block.
		copy(c.tag, c.k2)
		c.tag[0] ^= 0b10000000
	} else if c.nx == c.blockSize {
		subtle.XORBytes(c.tag, c.x, c.tag)
		subtle.XORBytes(c.tag, c.k1, c.tag)
	} else {
		subtle.XORBytes(c.tag, c.x, c.tag)
		c.tag[c.nx] ^= 0b10000000
		subtle.XORBytes(c.tag, c.k2, c.tag)
	}
	c.b.Encrypt(c.tag, c.tag)
	copy(tag, c.tag[:c.size])
	return tag
}

func (c *cmac) MAC(src []byte) []byte {
	c.Reset()
	c.Write(src)
	return c.Sum(nil)
}

// shiftLeft sets x to x << 1, and returns MSB₁(x).
func shiftLeft(x []byte) byte {
	var msb byte
	for i := len(x) - 1; i >= 0; i-- {
		msb, x[i] = x[i]>>7, x[i]<<1|msb
	}
	return msb
}

type lmac struct {
	b1, b2 cipher.Block
	pad    padding.Padding
	size   int
}

// NewLMAC returns an LMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 6
func NewLMAC(creator func(key []byte) (cipher.Block, error), key []byte, size int) BockCipherMAC {
	var b, b1, b2 cipher.Block
	var err error
	if b, err = creator(key); err != nil {
		panic(err)
	}
	if size <= 0 || size > b.BlockSize() {
		panic("cbcmac: invalid size")
	}
	blockSize := b.BlockSize()
	key1 := make([]byte, blockSize)
	key1[blockSize-1] = 0x01
	key2 := make([]byte, blockSize)
	key2[blockSize-1] = 0x02
	b.Encrypt(key1, key1)
	b.Encrypt(key2, key2)
	if b1, err = creator(key1); err != nil {
		panic(err)
	}
	if b2, err = creator(key2); err != nil {
		panic(err)
	}

	return &lmac{b1: b1, b2: b2, pad: padding.NewISO9797M2Padding(uint(blockSize)), size: size}
}

func (l *lmac) Size() int {
	return l.b1.BlockSize()
}

func (l *lmac) MAC(src []byte) []byte {
	src = l.pad.Pad(src)
	blockSize := l.b1.BlockSize()
	tag := make([]byte, blockSize)
	for len(src) > blockSize {
		subtle.XORBytes(tag, tag, src[:blockSize])
		l.b1.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	subtle.XORBytes(tag, tag, src[:blockSize])
	l.b2.Encrypt(tag, tag)
	return tag
}

type trCBCMAC struct {
	b    cipher.Block
	size int
}

// NewTRCBCMAC returns a TR-CBC-MAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 7
//
// Reference: TrCBC: Another look at CBC-MAC.
func NewTRCBCMAC(b cipher.Block, size int) BockCipherMAC {
	if size <= 0 || size > b.BlockSize() {
		panic("cbcmac: invalid size")
	}
	return &trCBCMAC{b: b, size: size}
}

func (t *trCBCMAC) Size() int {
	return t.size
}

func (t *trCBCMAC) MAC(src []byte) []byte {
	blockSize := t.b.BlockSize()
	tag := make([]byte, blockSize)
	padded := false
	if len(src) == 0 || len(src)%blockSize != 0 {
		pad := padding.NewISO9797M2Padding(uint(blockSize))
		src = pad.Pad(src)
		padded = true
	}
	for len(src) > 0 {
		subtle.XORBytes(tag, tag, src[:blockSize])
		t.b.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	if padded {
		return tag[blockSize-t.size:]
	}
	return tag[:t.size]
}

type cbcrMAC struct {
	b    cipher.Block
	size int
}

// NewCBCRMAC returns a CBCRMAC instance that implements MAC with the given block cipher.
// GB/T 15821.1-2020 MAC scheme 8
//
// Reference: CBCR: CBC MAC with rotating transformations.
func NewCBCRMAC(b cipher.Block, size int) BockCipherMAC {
	if size <= 0 || size > b.BlockSize() {
		panic("cbcmac: invalid size")
	}
	return &cbcrMAC{b: b, size: size}
}

func (c *cbcrMAC) Size() int {
	return c.size
}

func (c *cbcrMAC) MAC(src []byte) []byte {
	blockSize := c.b.BlockSize()
	tag := make([]byte, blockSize)
	c.b.Encrypt(tag, tag)
	padded := false
	if len(src) == 0 || len(src)%blockSize != 0 {
		pad := padding.NewISO9797M2Padding(uint(blockSize))
		src = pad.Pad(src)
		padded = true
	}

	for len(src) > blockSize {
		subtle.XORBytes(tag, tag, src[:blockSize])
		c.b.Encrypt(tag, tag)
		src = src[blockSize:]
	}
	subtle.XORBytes(tag, tag, src[:blockSize])
	if padded {
		shiftLeft(tag)
	} else {
		shiftRight(tag)
	}
	c.b.Encrypt(tag, tag)
	return tag[:c.size]
}

func shiftRight(x []byte) {
	var lsb byte
	for i := 0; i < len(x); i++ {
		lsb, x[i] = x[i]<<7, x[i]>>1|lsb
	}
	x[0] ^= lsb
}
