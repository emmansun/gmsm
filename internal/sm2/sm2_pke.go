// Copyright 2026 Sun Yimin. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sm2

import (
	"crypto/subtle"
	"errors"
	"io"

	"github.com/emmansun/gmsm/internal/bigmod"
	"github.com/emmansun/gmsm/internal/sm2ec"
	"github.com/emmansun/gmsm/internal/sm3"
	_subtle "github.com/emmansun/gmsm/internal/subtle"
)

const maxRetryLimit = 100

var ErrDecryption = errors.New("sm2: decryption error")

// Ciphertext represents an SM2 public key encryption result.
type Ciphertext struct {
	C1     *sm2ec.SM2P256Point
	C2, C3 []byte
}

func NewCiphertext(c1, c2, c3 []byte) (*Ciphertext, error) {
	c := P256()
	C1, err := c.newPoint().SetBytes(c1)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{C1: C1, C2: c2, C3: c3}, nil
}

func Encrypt(rand io.Reader, pub *PublicKey, msg []byte) (*Ciphertext, error) {
	if len(msg) == 0 {
		return nil, errors.New("sm2: message cannot be empty")
	}
	c := P256()
	Q, err := c.newPoint().SetBytes(pub.q)
	if err != nil {
		return nil, err
	}
	retryCount := 0
	randfunc := randFuncFac(rand)
	for {
		k, C1, err := randomPoint(c, randfunc, false)
		if err != nil {
			return nil, err
		}
		C2, err := Q.ScalarMult(Q, k.Bytes(c.N))
		if err != nil {
			return nil, err
		}
		C2Bytes := C2.Bytes()[1:]
		c2 := sm3.Kdf(C2Bytes, len(msg))
		if _subtle.ConstantTimeAllZero(c2) == 1 {
			retryCount++
			if retryCount > maxRetryLimit {
				return nil, errors.New("sm2: failed to calculate valid t, tried max retry limit")
			}
			continue
		}
		//A6, C2 = M + t;
		subtle.XORBytes(c2, msg, c2)

		//A7, C3 = hash(x2||M||y2)
		md := sm3.New()
		md.Write(C2Bytes[:len(C2Bytes)/2])
		md.Write(msg)
		md.Write(C2Bytes[len(C2Bytes)/2:])
		c3 := md.Sum(nil)
		return &Ciphertext{C1: C1, C2: c2, C3: c3}, nil
	}
}

func Decrypt(priv *PrivateKey, ciphertext *Ciphertext) ([]byte, error) {
	c := P256()
	d, err := bigmod.NewNat().SetBytes(priv.d, c.N)
	if err != nil {
		return nil, ErrDecryption
	}
	C1 := ciphertext.C1
	C2, err := C1.ScalarMult(C1, d.Bytes(c.N))
	if err != nil {
		return nil, ErrDecryption
	}
	C2Bytes := C2.Bytes()[1:]
	msgLen := len(ciphertext.C2)
	msg := sm3.Kdf(C2Bytes, msgLen)
	if _subtle.ConstantTimeAllZero(msg) == 1 {
		return nil, ErrDecryption
	}
	//B5, calculate msg = c2 ^ t
	subtle.XORBytes(msg, ciphertext.C2, msg)

	md := sm3.New()
	md.Write(C2Bytes[:len(C2Bytes)/2])
	md.Write(msg)
	md.Write(C2Bytes[len(C2Bytes)/2:])
	u := md.Sum(nil)
	if subtle.ConstantTimeCompare(u, ciphertext.C3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}
