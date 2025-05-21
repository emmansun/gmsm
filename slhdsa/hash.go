// Copyright 2025 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build go1.24

package slhdsa

import (
	"crypto/hmac"
	"hash"
)

type hashOperations interface {
	f(pk *PublicKey, address adrsOperations, m1, out []byte)
	h(pk *PublicKey, address adrsOperations, m1, m2, out []byte)
	t(pk *PublicKey, address adrsOperations, ml, out []byte)
	hMsg(pk *PublicKey, R, mPrefix, M, out []byte)
	prf(sk *PrivateKey, address adrsOperations, out []byte)
	prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte)
}

type shakeOperations struct{}

func (shakeOperations) f(pk *PublicKey, address adrsOperations, m1, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(address.bytes())
	pk.shake.Write(m1[:pk.params.n])
	pk.shake.Read(out[:pk.params.n])
}

func (shakeOperations) h(pk *PublicKey, address adrsOperations, m1, m2, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(address.bytes())
	pk.shake.Write(m1[:pk.params.n])
	pk.shake.Write(m2[:pk.params.n])
	pk.shake.Read(out[:pk.params.n])
}

func (shakeOperations) t(pk *PublicKey, address adrsOperations, ml, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(address.bytes())
	pk.shake.Write(ml)
	pk.shake.Read(out[:pk.params.n])
}

func (shakeOperations) hMsg(pk *PublicKey, R, mPrefix, M, out []byte) {
	pk.shake.Reset()
	pk.shake.Write(R[:pk.params.n])
	pk.shake.Write(pk.seed[:pk.params.n])
	pk.shake.Write(pk.root[:pk.params.n])
	pk.shake.Write(mPrefix)
	pk.shake.Write(M)
	pk.shake.Read(out[:pk.params.m])
}

func (shakeOperations) prf(sk *PrivateKey, address adrsOperations, out []byte) {
	sk.shake.Reset()
	sk.shake.Write(sk.PublicKey.seed[:sk.params.n])
	sk.shake.Write(address.bytes())
	sk.shake.Write(sk.seed[:sk.params.n])
	sk.shake.Read(out[:sk.params.n])
}

func (shakeOperations) prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte) {
	sk.shake.Reset()
	sk.shake.Write(sk.prf[:sk.params.n])
	sk.shake.Write(optRand)
	sk.shake.Write(mPrefix)
	sk.shake.Write(m)
	sk.shake.Read(out[:sk.params.n])
}

type sha2Operations struct{}

func (sha2Operations) f(pk *PublicKey, address adrsOperations, m1, out []byte) {
	var zeros [64]byte
	pk.md.Reset()
	pk.md.Write(pk.seed[:pk.params.n])
	pk.md.Write(zeros[:64-pk.params.n])
	pk.md.Write(address.bytes())
	pk.md.Write(m1[:pk.params.n])
	pk.md.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Operations) h(pk *PublicKey, address adrsOperations, m1, m2, out []byte) {
	var zeros [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(zeros[:uint32(pk.mdBig.BlockSize())-pk.params.n])
	pk.mdBig.Write(address.bytes())
	pk.mdBig.Write(m1[:pk.params.n])
	pk.mdBig.Write(m2[:pk.params.n])
	pk.mdBig.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Operations) t(pk *PublicKey, address adrsOperations, ml, out []byte) {
	var zeros [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(zeros[:uint32(pk.mdBig.BlockSize())-pk.params.n])
	pk.mdBig.Write(address.bytes())
	pk.mdBig.Write(ml)
	pk.mdBig.Sum(zeros[:0])
	copy(out, zeros[:pk.params.n])
}

func (sha2Operations) prfMsg(sk *PrivateKey, optRand, mPrefix, m, out []byte) {
	var buf [128]byte
	mac := hmac.New(sk.mdBigFactory, sk.prf[:sk.params.n])
	mac.Write(optRand)
	mac.Write(mPrefix)
	mac.Write(m)
	mac.Sum(buf[:0])
	copy(out, buf[:sk.params.n])
}

func (sha2Operations) prf(sk *PrivateKey, address adrsOperations, out []byte) {
	var zeros [128]byte
	sk.md.Reset()
	sk.md.Write(sk.PublicKey.seed[:sk.params.n])
	sk.md.Write(zeros[:64-sk.params.n])
	sk.md.Write(address.bytes())
	sk.md.Write(sk.seed[:sk.params.n])
	sk.md.Sum(zeros[:0])
	copy(out, zeros[:sk.params.n])
}

func (sha2Operations) hMsg(pk *PublicKey, R, mPrefix, M, out []byte) {
	var buf [128]byte
	pk.mdBig.Reset()
	pk.mdBig.Write(R[:pk.params.n])
	pk.mdBig.Write(pk.seed[:pk.params.n])
	pk.mdBig.Write(pk.root[:pk.params.n])
	pk.mdBig.Write(mPrefix)
	pk.mdBig.Write(M)
	pk.mdBig.Sum(buf[:0])
	mgf1([][]byte{R[:pk.params.n], pk.seed[:pk.params.n], buf[:pk.mdBig.Size()]}, pk.mdBig, out[:pk.params.m])
}

func mgf1(seeds [][]byte, h hash.Hash, out []byte) {
	var counter uint32
	var buff [128]byte
	size := h.Size()
	maskLen := len(out)
	for i := 0; i < maskLen; i += size {
		h.Reset()
		for _, seed := range seeds {
			h.Write(seed)
		}
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		h.Sum(buff[:0])
		copy(out[i:], buff[:size])
		counter++
	}
}
