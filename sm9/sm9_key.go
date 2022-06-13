package sm9

import (
	"errors"
	"io"
	"math/big"
	"sync"

	"golang.org/x/crypto/cryptobyte"
)

type SignMasterPrivateKey struct {
	SignMasterPublicKey
	D *big.Int
}

type SignMasterPublicKey struct {
	MasterPublicKey *G2
	pairOnce        sync.Once
	basePoint       *GT
}

type SignPrivateKey struct {
	PrivateKey *G1
	SignMasterPublicKey
}

type EncryptMasterPrivateKey struct {
	EncryptMasterPublicKey
	D *big.Int
}

type EncryptMasterPublicKey struct {
	MasterPublicKey *G1
	pairOnce        sync.Once
	basePoint       *GT
}

type EncryptPrivateKey struct {
	PrivateKey *G2
	EncryptMasterPublicKey
}

// GenerateSignMasterKey generates a master public and private key pair for DSA usage.
func GenerateSignMasterKey(rand io.Reader) (*SignMasterPrivateKey, error) {
	k, err := randFieldElement(rand)
	if err != nil {
		return nil, err
	}

	priv := new(SignMasterPrivateKey)
	priv.D = k
	priv.MasterPublicKey = new(G2).ScalarBaseMult(k)
	return priv, nil
}

// MarshalASN1 marshal sign master private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (master *SignMasterPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BigInt(master.D)
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to sign master private key
func (master *SignMasterPrivateKey) UnmarshalASN1(der []byte) error {
	input := cryptobyte.String(der)
	d := &big.Int{}
	if !input.ReadASN1Integer(d) || !input.Empty() {
		return errors.New("sm9: invalid sign master key asn1 data")
	}
	master.D = d
	master.MasterPublicKey = new(G2).ScalarBaseMult(d)
	return nil
}

// GenerateUserKey generate an user dsa key.
func (master *SignMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*SignPrivateKey, error) {
	var id []byte
	id = append(id, uid...)
	id = append(id, hid)

	t1 := hashH1(id)
	t1.Add(t1, master.D)
	if t1.Sign() == 0 {
		return nil, errors.New("sm9: need to re-generate sign master private key")
	}
	t1 = fermatInverse(t1, Order)
	t2 := new(big.Int).Mul(t1, master.D)
	t2.Mod(t2, Order)

	priv := new(SignPrivateKey)
	priv.SignMasterPublicKey = master.SignMasterPublicKey
	priv.PrivateKey = new(G1).ScalarBaseMult(t2)

	return priv, nil
}

// Public returns the public key corresponding to priv.
func (master *SignMasterPrivateKey) Public() *SignMasterPublicKey {
	return &master.SignMasterPublicKey
}

// MarshalASN1 marshal sign master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (pub *SignMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalUncompressed())
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to sign master public key
func (pub *SignMasterPublicKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	input := cryptobyte.String(der)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid sign master public key asn1 data")
	}
	if bytes[0] != 4 {
		return errors.New("sm9: invalid prefix of sign master public key")
	}
	g2 := new(G2)
	_, err := g2.Unmarshal(bytes[1:])
	if err != nil {
		return err
	}
	pub.MasterPublicKey = g2
	return nil
}

// GenerateUserPublicKey generate user sign public key
func (pub *SignMasterPublicKey) GenerateUserPublicKey(uid []byte, hid byte) *G2 {
	var buffer []byte
	buffer = append(buffer, uid...)
	buffer = append(buffer, hid)
	h1 := hashH1(buffer)
	p := new(G2).ScalarBaseMult(h1)
	p.Add(p, pub.MasterPublicKey)
	return p
}

// MasterPublic returns the master public key corresponding to priv.
func (priv *SignPrivateKey) MasterPublic() *SignMasterPublicKey {
	return &priv.SignMasterPublicKey
}

// SetMasterPublicKey bind the sign master public key to it.
func (priv *SignPrivateKey) SetMasterPublicKey(pub *SignMasterPublicKey) {
	if priv.SignMasterPublicKey.MasterPublicKey == nil {
		priv.SignMasterPublicKey = *pub
	}
}

// MarshalASN1 marshal sign user private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (priv *SignPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalUncompressed())
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to sign user private key
// Note, priv's SignMasterPublicKey should be handled separately.
func (priv *SignPrivateKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	input := cryptobyte.String(der)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid sign user private key asn1 data")
	}
	if bytes[0] != 4 {
		return errors.New("sm9: invalid prefix of sign user private key")
	}
	g := new(G1)
	_, err := g.Unmarshal(bytes[1:])
	if err != nil {
		return err
	}
	priv.PrivateKey = g
	return nil
}

// GenerateEncryptMasterKey generates a master public and private key pair for encryption usage.
func GenerateEncryptMasterKey(rand io.Reader) (*EncryptMasterPrivateKey, error) {
	k, err := randFieldElement(rand)
	if err != nil {
		return nil, err
	}

	priv := new(EncryptMasterPrivateKey)
	priv.D = k
	priv.MasterPublicKey = new(G1).ScalarBaseMult(k)
	return priv, nil
}

// GenerateUserKey generate an user key for encryption.
func (master *EncryptMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*EncryptPrivateKey, error) {
	var id []byte
	id = append(id, uid...)
	id = append(id, hid)

	t1 := hashH1(id)
	t1.Add(t1, master.D)
	if t1.Sign() == 0 {
		return nil, errors.New("sm9: need to re-generate encrypt master private key")
	}
	t1 = fermatInverse(t1, Order)
	t2 := new(big.Int).Mul(t1, master.D)
	t2.Mod(t2, Order)

	priv := new(EncryptPrivateKey)
	priv.EncryptMasterPublicKey = master.EncryptMasterPublicKey
	priv.PrivateKey = new(G2).ScalarBaseMult(t2)

	return priv, nil
}

// Public returns the public key corresponding to priv.
func (master *EncryptMasterPrivateKey) Public() *EncryptMasterPublicKey {
	return &master.EncryptMasterPublicKey
}

// MarshalASN1 marshal encrypt master private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (master *EncryptMasterPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BigInt(master.D)
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to encrpt master private key
func (master *EncryptMasterPrivateKey) UnmarshalASN1(der []byte) error {
	input := cryptobyte.String(der)
	d := &big.Int{}
	if !input.ReadASN1Integer(d) || !input.Empty() {
		return errors.New("sm9: invalid encrpt master key asn1 data")
	}
	master.D = d
	master.MasterPublicKey = new(G1).ScalarBaseMult(d)
	return nil
}

// MarshalASN1 marshal encrypt master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (pub *EncryptMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.MasterPublicKey.MarshalUncompressed())
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to encrypt master public key
func (pub *EncryptMasterPublicKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	input := cryptobyte.String(der)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid encrypt master public key asn1 data")
	}
	if bytes[0] != 4 {
		return errors.New("sm9: invalid prefix of encrypt master public key")
	}
	g := new(G1)
	_, err := g.Unmarshal(bytes[1:])
	if err != nil {
		return err
	}
	pub.MasterPublicKey = g
	return nil
}

// MasterPublic returns the master public key corresponding to priv.
func (priv *EncryptPrivateKey) MasterPublic() *EncryptMasterPublicKey {
	return &priv.EncryptMasterPublicKey
}

// SetMasterPublicKey bind the encrypt master public key to it.
func (priv *EncryptPrivateKey) SetMasterPublicKey(pub *EncryptMasterPublicKey) {
	if priv.EncryptMasterPublicKey.MasterPublicKey == nil {
		priv.EncryptMasterPublicKey = *pub
	}
}

// MarshalASN1 marshal encrypt user private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (priv *EncryptPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.PrivateKey.MarshalUncompressed())
	return b.Bytes()
}

// UnmarshalASN1 unmarsal der data to encrypt user private key
// Note, priv's EncryptMasterPublicKey should be handled separately.
func (priv *EncryptPrivateKey) UnmarshalASN1(der []byte) error {
	var bytes []byte
	input := cryptobyte.String(der)
	if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return errors.New("sm9: invalid encrypt user private key asn1 data")
	}
	if bytes[0] != 4 {
		return errors.New("sm9: invalid prefix of encrypt user private key")
	}
	g := new(G2)
	_, err := g.Unmarshal(bytes[1:])
	if err != nil {
		return err
	}
	priv.PrivateKey = g
	return nil
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}
