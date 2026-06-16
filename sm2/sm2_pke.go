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
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/internal/sm2"
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
// A fresh buffer is always allocated to avoid aliasing issues when c1/c2/c3 are sub-slices of
// the same underlying array (as returned by parseCiphertext).
func (order ciphertextSplicingOrder) spliceCiphertext(c1, c2, c3 []byte) ([]byte, error) {
	result := make([]byte, len(c1)+len(c2)+len(c3))
	switch order {
	case C1C3C2:
		n := copy(result, c1)
		n += copy(result[n:], c3)
		copy(result[n:], c2)
	case C1C2C3:
		n := copy(result, c1)
		n += copy(result[n:], c2)
		copy(result[n:], c3)
	default:
		return nil, errors.New("sm2: invalid ciphertext splicing order")
	}
	return result, nil
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
		internalPub, err := publicKeyToInternal(pub)
		if err != nil {
			return nil, err
		}
		ciphertext, err := sm2.Encrypt(random, internalPub, msg)
		if err != nil {
			return nil, err
		}
		if opts.ciphertextEncoding == ENCODING_PLAIN {
			c1 := marshalCiphertextPoint(ciphertext, opts.pointMarshalMode)
			return encodeCiphertext(opts, c1, ciphertext.C2, ciphertext.C3)
		}
		return encodingCiphertextASN1(ciphertext.C1.Bytes(), ciphertext.C2, ciphertext.C3)
	default:
		return nil, errors.New("sm2: curve not supported by Encrypt")
	}
}

func marshalCiphertextPoint(ciphertext *sm2.Ciphertext, mode pointMarshalMode) []byte {
	if mode == MarshalCompressed {
		return ciphertext.C1.BytesCompressed()
	}
	return ciphertext.C1.Bytes()
}

func encodeCiphertext(opts *EncrypterOpts, c1, c2, c3 []byte) ([]byte, error) {
	return opts.ciphertextSplicingOrder.spliceCiphertext(c1, c2, c3)
}

func encodingCiphertextASN1(c1, c2, c3 []byte) ([]byte, error) {
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
		return decryptSM2EC(priv, ciphertext, opts)
	default:
		return nil, errors.New("sm2: curve not supported by Decrypt")
	}
}

func decryptSM2EC(priv *PrivateKey, ciphertext []byte, opts *DecrypterOpts) ([]byte, error) {
	c1, c2, c3, err := parseCiphertext(ciphertext, opts)
	if err != nil {
		return nil, ErrDecryption
	}
	ct, err := sm2.NewCiphertext(c1, c2, c3)
	if err != nil {
		return nil, ErrDecryption
	}
	internalPriv, err := privateKeyToInternal(priv)
	if err != nil {
		return nil, ErrDecryption
	}
	plaintext, err := sm2.Decrypt(internalPriv, ct)
	if err != nil {
		return nil, ErrDecryption
	}
	return plaintext, nil
}

func isCompressedPrefix(prefix byte) bool {
	return prefix == compressed02 || prefix == compressed03
}

func c1LengthFromPrefix(prefix byte, byteLen int) (int, bool, error) {
	switch prefix {
	case byte(asn1.SEQUENCE):
		return 0, true, nil
	case uncompressed:
		return 1 + 2*byteLen, false, nil
	case compressed02, compressed03:
		return 1 + byteLen, false, nil
	default:
		return 0, false, errors.New("sm2: invalid/unsupported ciphertext format")
	}
}

// parseCiphertext parses the given ciphertext according to the specified SM2 curve and decryption options.
// It returns the parsed SM2 point (C1), the decrypted message (C2), the message digest (C3), and an error if any.
func parseCiphertext(ciphertext []byte, opts *DecrypterOpts) ([]byte, []byte, []byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil, nil, errors.New("sm2: invalid/unsupported ciphertext format")
	}

	bitSize := P256().Params().BitSize
	byteLen := (bitSize + 7) / 8
	splicingOrder := C1C3C2
	if opts != nil {
		splicingOrder = opts.ciphertextSplicingOrder
	}

	c1Len, isASN1, err := c1LengthFromPrefix(ciphertext[0], byteLen)
	if err != nil {
		return nil, nil, nil, err
	}
	if isASN1 {
		return parseCiphertextASN1(ciphertext)
	}
	if len(ciphertext) < c1Len+sm3.Size {
		return nil, nil, nil, errCiphertextTooShort
	}
	c2, c3 := splicingOrder.splitC2C3(ciphertext[c1Len:])
	return ciphertext[:c1Len], c2, c3, nil
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

func parseCiphertextASN1(ciphertext []byte) ([]byte, []byte, []byte, error) {
	x1, y1, c2, c3, err := unmarshalASN1Ciphertext(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	c1, err := pointFromAffine(P256(), x1, y1)
	if err != nil {
		return nil, nil, nil, err
	}
	return c1, c2, c3, nil
}

// AdjustCiphertextSplicingOrder utility method to change c2 c3 order
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	if from == to {
		return ciphertext, nil
	}
	c1, c2, c3, err := parseCiphertext(ciphertext, NewPlainDecrypterOpts(from))
	if err != nil {
		return nil, err
	}
	opts := NewPlainEncrypterOpts(MarshalUncompressed, to)
	if isCompressedPrefix(ciphertext[0]) {
		opts.pointMarshalMode = MarshalCompressed
	}
	return encodeCiphertext(opts, c1, c2, c3)
}

// ASN1Ciphertext2Plain utility method to convert ASN.1 encoding ciphertext to plain encoding format
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = defaultEncrypterOpts
	}
	c1, c2, c3, err := parseCiphertextASN1(ciphertext)
	if err != nil {
		return nil, err
	}
	return encodeCiphertext(opts, c1, c2, c3)
}

// PlainCiphertext2ASN1 utility method to convert plain encoding ciphertext to ASN.1 encoding format
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	c1, c2, c3, err := parseCiphertext(ciphertext, NewPlainDecrypterOpts(from))
	if err != nil {
		return nil, err
	}
	return encodingCiphertextASN1(c1, c2, c3)
}
