package sm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"gmsm/sm3"
	"io"
	"math/big"
)

const (
	Uncompressed  byte = 0x04
	Compressed_02 byte = 0x02
	Compressed_03 byte = 0x03
	Mixed_06      byte = 0x06
	Mixed_07      byte = 0x07
)

///////////////// below code ship from golan crypto/ecdsa ////////////////////
var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

///////////////////////////////////////////////////////////////////////////////////
func kdf(z []byte, len int) ([]byte, bool) {
	limit := (len + sm3.Size - 1) / sm3.Size
	sm3Hasher := sm3.New()
	var countBytes [4]byte
	var ct uint32 = 1
	k := make([]byte, len+sm3.Size-1)
	for i := 0; i < limit; i++ {
		binary.BigEndian.PutUint32(countBytes[:], ct)
		sm3Hasher.Write(z)
		sm3Hasher.Write(countBytes[:])
		copy(k[i*sm3.Size:], sm3Hasher.Sum(nil))
		ct++
		sm3Hasher.Reset()
	}
	for i := 0; i < len; i++ {
		if k[i] != 0 {
			return k[:len], true
		}
	}
	return k, false
}

func calculateC3(curve elliptic.Curve, x2, y2 *big.Int, msg []byte) []byte {
	hasher := sm3.New()
	hasher.Write(toBytes(curve, x2))
	hasher.Write(msg)
	hasher.Write(toBytes(curve, y2))
	return hasher.Sum(nil)
}

// Encrypt sm2 encrypt implementation
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	curve := pub.Curve
	msgLen := len(msg)
	for {
		//A1, generate random k
		k, err := randFieldElement(curve, random)
		if err != nil {
			return nil, err
		}

		//A2, calculate C1 = k * G
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		c1 := point2CompressedBytes(curve, x1, y1)

		//A3, skipped
		//A4, calculate k * P (point of Public Key)
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		//A5, calculate t=KDF(x2||y2, klen)
		t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
		if !success {
			fmt.Println("A5, failed to get valid t")
			continue
		}

		//A6, C2 = M + t;
		c2 := make([]byte, msgLen)
		for i := 0; i < msgLen; i++ {
			c2[i] = msg[i] ^ t[i]
		}

		//A7, C3 = hash(x2||M||y2)
		c3 := calculateC3(curve, x2, y2, msg)

		return append(append(c1, c2...), c3...), nil
	}
}

// Decrypt sm2 decrypt implementation
func Decrypt(priv *ecdsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errors.New("invalid ciphertext length")
	}
	curve := priv.Curve
	// B1, get C1, and check C1
	x1, y1, c2Start, err := bytes2Point(curve, ciphertext)
	if err != nil {
		return nil, err
	}
	if !curve.IsOnCurve(x1, y1) {
		return nil, fmt.Errorf("point c1 is not on curve %s", curve.Params().Name)
	}

	//B2 is ignored
	//B3, calculate x2, y2
	x2, y2 := curve.ScalarMult(x1, y1, priv.D.Bytes())

	//B4, calculate t=KDF(x2||y2, klen)
	c2 := ciphertext[c2Start : ciphertextLen-sm3.Size]
	msgLen := len(c2)
	t, success := kdf(append(toBytes(curve, x2), toBytes(curve, y2)...), msgLen)
	if !success {
		return nil, errors.New("invalid cipher text")
	}

	//B5, calculate msg = c2 ^ t
	msg := make([]byte, msgLen)
	for i := 0; i < msgLen; i++ {
		msg[i] = c2[i] ^ t[i]
	}

	//B6, calculate hash and compare it
	c3 := ciphertext[ciphertextLen-sm3.Size:]
	u := calculateC3(curve, x2, y2, msg)
	for i := 0; i < sm3.Size; i++ {
		if c3[i] != u[i] {
			return nil, errors.New("invalid hash value")
		}
	}

	return msg, nil
}
