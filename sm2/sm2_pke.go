// Package sm2 implements ShangMi(SM) sm2 digital signature, public key encryption and key exchange algorithms.
package sm2

// Further references:
//   [NSA]: Suite B implementer's guide to FIPS 186-3
//     http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.182.4503&rep=rep1&type=pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf
//   [GM/T]: SM2 GB/T 32918.2-2016, GB/T 32918.4-2016
//

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/internal/bigmod"
	_sm2ec "github.com/emmansun/gmsm/internal/sm2ec"
	_subtle "github.com/emmansun/gmsm/internal/subtle"
	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	uncompressed byte = 0x04
	compressed02 byte = 0x02
	compressed03 byte = compressed02 | 0x01
	hybrid06     byte = 0x06
	hybrid07     byte = hybrid06 | 0x01
)

type pointMarshalMode byte

const (
	//MarshalUncompressed uncompressed marshal mode
	MarshalUncompressed pointMarshalMode = iota
	//MarshalCompressed compressed marshal mode
	MarshalCompressed
	//MarshalHybrid hybrid marshal mode
	MarshalHybrid
)

type ciphertextSplicingOrder byte

const (
	C1C3C2 ciphertextSplicingOrder = iota
	C1C2C3
)

// splitC2C3 splits the given ciphertext into two parts, C2 and C3, based on the splicing order.
// If the order is C1C3C2, it returns the first sm3.Size bytes as C3 and the rest as C2.
// Otherwise, it returns the first part as C2 and the last sm3.Size bytes as C3.
func (order ciphertextSplicingOrder) splitC2C3(ciphertext []byte) ([]byte, []byte) {
	if order == C1C3C2 {
		return ciphertext[sm3.Size:], ciphertext[:sm3.Size]
	}
	return ciphertext[:len(ciphertext)-sm3.Size], ciphertext[len(ciphertext)-sm3.Size:]
}

// spliceCiphertext splices the given ciphertext components together based on the splicing order.
func (order ciphertextSplicingOrder) spliceCiphertext(c1, c2, c3 []byte) ([]byte, error) {
	switch order {
	case C1C3C2:
		return append(append(c1, c3...), c2...), nil
	case C1C2C3:
		return append(append(c1, c2...), c3...), nil
	default:
		return nil, errors.New("sm2: invalid ciphertext splicing order")
	}
}

type ciphertextEncoding byte

const (
	ENCODING_PLAIN ciphertextEncoding = iota
	ENCODING_ASN1
)

// EncrypterOpts represents the options for the SM2 encryption process.
// It includes settings for ciphertext encoding, point marshaling mode,
// and the order in which the ciphertext components are spliced together.
type EncrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	pointMarshalMode        pointMarshalMode
	ciphertextSplicingOrder ciphertextSplicingOrder
}

// DecrypterOpts represents the options for the decryption process.
// It includes settings for how the ciphertext is encoded and how the
// components of the ciphertext are spliced together.
//
// Fields:
//   - ciphertextEncoding: Specifies the encoding format of the ciphertext.
//   - ciphertextSplicingOrder: Defines the order in which the components
//     of the ciphertext are spliced together.
type DecrypterOpts struct {
	ciphertextEncoding      ciphertextEncoding
	ciphertextSplicingOrder ciphertextSplicingOrder
}

// NewPlainEncrypterOpts creates a SM2 non-ASN1 encrypter options.
func NewPlainEncrypterOpts(marshalMode pointMarshalMode, splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{ENCODING_PLAIN, marshalMode, splicingOrder}
}

// NewPlainDecrypterOpts creates a SM2 non-ASN1 decrypter options.
func NewPlainDecrypterOpts(splicingOrder ciphertextSplicingOrder) *DecrypterOpts {
	return &DecrypterOpts{ENCODING_PLAIN, splicingOrder}
}

var (
	defaultEncrypterOpts = &EncrypterOpts{ENCODING_PLAIN, MarshalUncompressed, C1C3C2}

	ASN1EncrypterOpts = &EncrypterOpts{ENCODING_ASN1, MarshalUncompressed, C1C3C2}

	ASN1DecrypterOpts = &DecrypterOpts{ENCODING_ASN1, C1C3C2}
)

const maxRetryLimit = 100

var errCiphertextTooShort = errors.New("sm2: ciphertext too short")

// EncryptASN1 sm2 encrypt and output ASN.1 result, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func EncryptASN1(random io.Reader, pub *ecdsa.PublicKey, msg []byte) ([]byte, error) {
	return Encrypt(random, pub, msg, ASN1EncrypterOpts)
}

// Encrypt sm2 encrypt implementation, compliance with GB/T 32918.4-2016.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
// Most applications should use [crypto/rand.Reader] as random.
func Encrypt(random io.Reader, pub *ecdsa.PublicKey, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	//A3, requirement is to check if h*P is infinite point, h is 1
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return nil, errors.New("sm2: public key point is the infinity")
	}
	if len(msg) == 0 {
		return nil, nil
	}
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	switch pub.Curve.Params() {
	case P256().Params():
		return encryptSM2EC(p256(), pub, random, msg, opts)
	default:
		return encryptLegacy(random, pub, msg, opts)
	}
}

func encryptSM2EC(c *sm2Curve, pub *ecdsa.PublicKey, random io.Reader, msg []byte, opts *EncrypterOpts) ([]byte, error) {
	Q, err := c.pointFromAffine(pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	retryCount := 0
	for {
		k, C1, err := randomPoint(c, random, false)
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
				return nil, fmt.Errorf("sm2: A5, failed to calculate valid t, tried %v times", retryCount)
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

		if opts.ciphertextEncoding == ENCODING_PLAIN {
			return encodeCiphertext(opts, C1, c2, c3)
		}
		return encodingCiphertextASN1(C1, c2, c3)
	}
}

func encodeCiphertext(opts *EncrypterOpts, C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	var c1 []byte
	switch opts.pointMarshalMode {
	case MarshalCompressed:
		c1 = C1.BytesCompressed()
	default:
		c1 = C1.Bytes()
	}
	return opts.ciphertextSplicingOrder.spliceCiphertext(c1, c2, c3)
}

func encodingCiphertextASN1(C1 *_sm2ec.SM2P256Point, c2, c3 []byte) ([]byte, error) {
	c1 := C1.Bytes()
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, c1[1:len(c1)/2+1])
		addASN1IntBytes(b, c1[len(c1)/2+1:])
		b.AddASN1OctetString(c3)
		b.AddASN1OctetString(c2)
	})
	return b.Bytes()
}

// Decrypt decrypts ciphertext msg to plaintext.
// The opts argument should be appropriate for the primitive used.
// Compliance with GB/T 32918.4-2016 chapter 7.
func (priv *PrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	var sm2Opts *DecrypterOpts
	sm2Opts, _ = opts.(*DecrypterOpts)
	return decrypt(priv, msg, sm2Opts)
}

// Decrypt sm2 decrypt implementation by default DecrypterOpts{C1C3C2}.
// Compliance with GB/T 32918.4-2016.
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	return decrypt(priv, ciphertext, nil)
}

// ErrDecryption represents a failure to decrypt a message.
// It is deliberately vague to avoid adaptive attacks.
var ErrDecryption = errors.New("sm2: decryption error")

func decrypt(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	ciphertextLen := len(ciphertext)
	if ciphertextLen <= 1+(priv.Params().BitSize/8)+sm3.Size {
		return nil, errCiphertextTooShort
	}
	switch priv.Curve.Params() {
	case P256().Params():
		return decryptSM2EC(p256(), priv, ciphertext, opts)
	default:
		return decryptLegacy(priv, ciphertext, opts)
	}
}

func decryptSM2EC(c *sm2Curve, priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	C1, c2, c3, err := parseCiphertext(c, ciphertext, opts)
	if err != nil {
		return nil, ErrDecryption
	}
	d, err := bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, ErrDecryption
	}

	C2, err := C1.ScalarMult(C1, d.Bytes(c.N))
	if err != nil {
		return nil, ErrDecryption
	}
	C2Bytes := C2.Bytes()[1:]
	msgLen := len(c2)
	msg := sm3.Kdf(C2Bytes, msgLen)
	if _subtle.ConstantTimeAllZero(c2) == 1 {
		return nil, ErrDecryption
	}

	//B5, calculate msg = c2 ^ t
	subtle.XORBytes(msg, c2, msg)

	md := sm3.New()
	md.Write(C2Bytes[:len(C2Bytes)/2])
	md.Write(msg)
	md.Write(C2Bytes[len(C2Bytes)/2:])
	u := md.Sum(nil)

	if subtle.ConstantTimeCompare(u, c3) == 1 {
		return msg, nil
	}
	return nil, ErrDecryption
}

// parseCiphertext parses the given ciphertext according to the specified SM2 curve and decryption options.
// It returns the parsed SM2 point (C1), the decrypted message (C2), the message digest (C3), and an error if any.
func parseCiphertext(c *sm2Curve, ciphertext []byte, opts *DecrypterOpts) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	bitSize := c.curve.Params().BitSize
	byteLen := (bitSize + 7) / 8
	splicingOrder := C1C3C2
	if opts != nil {
		splicingOrder = opts.ciphertextSplicingOrder
	}

	var ciphertextFormat byte = 0xff // invalid
	if len(ciphertext) > 0 {
		ciphertextFormat = ciphertext[0]
	}
	var c1Len int
	switch ciphertextFormat {
	case byte(asn1.SEQUENCE):
		return parseCiphertextASN1(c, ciphertext)
	case uncompressed:
		c1Len = 1 + 2*byteLen
	case compressed02, compressed03:
		c1Len = 1 + byteLen
	default:
		return nil, nil, nil, errors.New("sm2: invalid/unsupported ciphertext format")
	}
	if len(ciphertext) < c1Len+sm3.Size {
		return nil, nil, nil, errCiphertextTooShort
	}
	C1, err := c.newPoint().SetBytes(ciphertext[:c1Len])
	if err != nil {
		return nil, nil, nil, err
	}
	c2, c3 := splicingOrder.splitC2C3(ciphertext[c1Len:])
	return C1, c2, c3, nil
}

func unmarshalASN1Ciphertext(ciphertext []byte) (*big.Int, *big.Int, []byte, []byte, error) {
	var (
		x1, y1 = &big.Int{}, &big.Int{}
		c2, c3 []byte
		inner  cryptobyte.String
	)
	input := cryptobyte.String(ciphertext)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(x1) ||
		!inner.ReadASN1Integer(y1) ||
		!inner.ReadASN1Bytes(&c3, asn1.OCTET_STRING) ||
		!inner.ReadASN1Bytes(&c2, asn1.OCTET_STRING) ||
		!inner.Empty() {
		return nil, nil, nil, nil, errors.New("sm2: invalid asn1 format ciphertext")
	}
	return x1, y1, c2, c3, nil
}

func parseCiphertextASN1(c *sm2Curve, ciphertext []byte) (*_sm2ec.SM2P256Point, []byte, []byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	C1, err := c.pointFromAffine(x1, y1)
	if err != nil {
		return nil, nil, nil, err
	}
	return C1, c2, c3, nil
}

// AdjustCiphertextSplicingOrder utility method to change c2 c3 order
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	curve := p256()
	if from == to {
		return ciphertext, nil
	}
	C1, c2, c3, err := parseCiphertext(curve, ciphertext, NewPlainDecrypterOpts(from))
	if err != nil {
		return nil, err
	}
	opts := NewPlainEncrypterOpts(MarshalUncompressed, to)
	if ciphertext[0] == compressed02 || ciphertext[0] == compressed03 {
		opts.pointMarshalMode = MarshalCompressed
	}
	return encodeCiphertext(opts, C1, c2, c3)
}

// ASN1Ciphertext2Plain utility method to convert ASN.1 encoding ciphertext to plain encoding format
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	C1, c2, c3, err := parseCiphertextASN1(p256(), ciphertext)
	if err != nil {
		return nil, err
	}
	return encodeCiphertext(opts, C1, c2, c3)
}

// PlainCiphertext2ASN1 utility method to convert plain encoding ciphertext to ASN.1 encoding format
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	C1, c2, c3, err := parseCiphertext(p256(), ciphertext, NewPlainDecrypterOpts(from))
	if err != nil {
		return nil, err
	}
	return encodingCiphertextASN1(C1, c2, c3)
}
