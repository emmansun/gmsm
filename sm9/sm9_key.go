package sm9

import (
	"crypto"
	"crypto/subtle"
	"encoding/pem"

	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/internal/sm9"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignMasterPrivateKey is a signature master private key, generated by KGC
type SignMasterPrivateKey struct {
	privateKey []byte
	publicKey  *SignMasterPublicKey
	internal   *sm9.SignMasterPrivateKey
}

// SignMasterPublicKey is a signature master public key, generated by KGC
type SignMasterPublicKey struct {
	publicKey []byte
	internal  *sm9.SignMasterPublicKey
}

// SignPrivateKey is a signature private key, generated by KGC
type SignPrivateKey struct {
	privateKey []byte
	internal   *sm9.SignPrivateKey
}

// EncryptMasterPrivateKey is an encryption master private key, generated by KGC
type EncryptMasterPrivateKey struct {
	privateKey []byte
	publicKey  *EncryptMasterPublicKey
	internal   *sm9.EncryptMasterPrivateKey
}

// EncryptMasterPublicKey is an encryption master public key, generated by KGC
type EncryptMasterPublicKey struct {
	publicKey []byte
	internal  *sm9.EncryptMasterPublicKey
}

// EncryptPrivateKey is an encryption private key, generated by KGC
type EncryptPrivateKey struct {
	privateKey []byte
	internal   *sm9.EncryptPrivateKey
}

// GenerateSignMasterKey generates a signature master key pair for DSA usage.
func GenerateSignMasterKey(rand io.Reader) (*SignMasterPrivateKey, error) {
	priv, err := sm9.GenerateSignMasterKey(rand)
	if err != nil {
		return nil, err
	}
	master := &SignMasterPrivateKey{privateKey: priv.Bytes(), internal: priv}
	master.publicKey = &SignMasterPublicKey{publicKey: priv.PublicKey().Bytes(), internal: priv.PublicKey()}
	return master, nil
}

// Equal compares the receiver SignMasterPrivateKey with another SignMasterPrivateKey
// and returns true if they are equal, otherwise it returns false.
func (master *SignMasterPrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*SignMasterPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(master.privateKey, xx.privateKey) == 1
}

// Bytes returns the byte representation of the SignMasterPrivateKey.
// It converts the private key to a byte slice.
func (master *SignMasterPrivateKey) Bytes() []byte {
	var buf [32]byte
	return append(buf[:0], master.privateKey...)
}

// MarshalASN1 marshal sign master private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (master *SignMasterPrivateKey) MarshalASN1() ([]byte, error) {
	d := new(big.Int).SetBytes(master.privateKey)
	var b cryptobyte.Builder
	b.AddASN1BigInt(d)
	return b.Bytes()
}

// UnmarshalSignMasterPrivateKeyASN1 unmarsal der data to a signature master private key
func UnmarshalSignMasterPrivateKeyASN1(der []byte) (*SignMasterPrivateKey, error) {
	input := cryptobyte.String(der)
	d := &big.Int{}
	var inner cryptobyte.String
	var pubBytes []byte
	var err error
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(d) {
			return nil, errors.New("sm9: invalid ASN.1 data for signature master private key")
		}
		// Just parse it, didn't validate it
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return nil, errors.New("sm9: invalid ASN.1 data for signature master public key")
		}
	} else if !input.ReadASN1Integer(d) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for signature master private key")
	}

	priv, err := sm9.NewSignMasterPrivateKey(d.Bytes())
	if err != nil {
		return nil, err
	}

	master := &SignMasterPrivateKey{privateKey: priv.Bytes(), internal: priv}
	master.publicKey = &SignMasterPublicKey{
		publicKey: priv.PublicKey().Bytes(),
		internal:  priv.PublicKey(),
	}
	return master, nil
}

// GenerateUserKey generate a signature private key for the given user.
func (master *SignMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*SignPrivateKey, error) {
	priv, err := master.internal.GenerateUserKey(uid, hid)
	if err != nil {
		return nil, err
	}
	return &SignPrivateKey{privateKey: priv.Bytes(), internal: priv}, nil
}

// Public returns the public key corresponding to the private key.
func (master *SignMasterPrivateKey) PublicKey() *SignMasterPublicKey {
	return master.publicKey
}

func (master *SignMasterPrivateKey) Public() crypto.PublicKey {
	return master.PublicKey()
}

// Equal compares the receiver SignMasterPublicKey with another SignMasterPublicKey
// and returns true if they are equal, otherwise false.
func (pub *SignMasterPublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*SignMasterPublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pub.publicKey, xx.publicKey) == 1
}

// Bytes returns the byte representation of the SignMasterPublicKey.
// It calls the Bytes method on the underlying publicKey field.
func (pub *SignMasterPublicKey) Bytes() []byte {
	var buf [129]byte
	return append(buf[:0], pub.publicKey...)
}

// MarshalASN1 marshal signature master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (pub *SignMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.publicKey)
	return b.Bytes()
}

// MarshalCompressedASN1 marshal signature master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification, the curve point is in compressed form.
func (pub *SignMasterPublicKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.publicKey)
	return b.Bytes()
}

// UnmarshalSignMasterPublicKeyRaw unmarsal raw bytes data to signature master public key
func UnmarshalSignMasterPublicKeyRaw(bytes []byte) (pub *SignMasterPublicKey, err error) {
	pub = new(SignMasterPublicKey)
	pub.internal = new(sm9.SignMasterPublicKey)
	err = pub.internal.UnmarshalRaw(bytes)
	pub.publicKey = pub.internal.Bytes()
	return
}

// UnmarshalSignMasterPublicKeyASN1 unmarsal der data to signature master public key
func UnmarshalSignMasterPublicKeyASN1(der []byte) (*SignMasterPublicKey, error) {
	var bytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) ||
			!inner.Empty() {
			return nil, errors.New("sm9: invalid ASN.1 data for signature master public key")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for signature master public key")
	}
	return UnmarshalSignMasterPublicKeyRaw(bytes)
}

// ParseSignMasterPublicKeyPEM just for GMSSL, there are no Algorithm pkix.AlgorithmIdentifier
func ParseSignMasterPublicKeyPEM(data []byte) (*SignMasterPublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("sm9: failed to parse PEM block")
	}
	return UnmarshalSignMasterPublicKeyASN1(block.Bytes)
}

func (priv *SignPrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*SignPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv.privateKey, xx.privateKey) == 1
}

// Public returns the public key corresponding to the private key.
// Just to satisfy [crypto.Signer] interface.
func (priv *SignPrivateKey) Public() crypto.PublicKey {
	return nil
}

func (priv *SignPrivateKey) Bytes() []byte {
	var buf [65]byte
	return append(buf[:0], priv.privateKey...)
}

// MasterPublic returns the signature master public key corresponding to priv.
func (priv *SignPrivateKey) MasterPublic() *SignMasterPublicKey {
	masterKey := priv.internal.MasterPublic()
	return &SignMasterPublicKey{internal: masterKey, publicKey: masterKey.Bytes()}
}

// MarshalASN1 marshal signature private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (priv *SignPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.privateKey)
	return b.Bytes()
}

// MarshalCompressedASN1 marshal signature private key to asn.1 format data according
// SM9 cryptographic algorithm application specification, the curve point is in compressed form.
func (priv *SignPrivateKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.privateKey)
	return b.Bytes()
}

// UnmarshalSignPrivateKeyRaw unmarsal raw bytes data to signature private key
// Note, priv's SignMasterPublicKey should be handled separately.
func UnmarshalSignPrivateKeyRaw(bytes []byte) (*SignPrivateKey, error) {
	priv := new(SignPrivateKey)
	priv.internal = new(sm9.SignPrivateKey)
	err := priv.internal.UnmarshalRaw(bytes)
	if err != nil {
		return nil, err
	}
	priv.privateKey = priv.internal.Bytes()
	return priv, nil
}

// UnmarshalSignPrivateKeyASN1 unmarsal der data to signature private key
// Note, priv's SignMasterPublicKey should be handled separately.
func UnmarshalSignPrivateKeyASN1(der []byte) (*SignPrivateKey, error) {
	var bytes []byte
	var pubBytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) {
			return nil, errors.New("sm9: invalid ASN.1 data for signature private key")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return nil, errors.New("sm9: invalid ASN.1 data for signature master public key")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for signature private key")
	}

	priv, err := UnmarshalSignPrivateKeyRaw(bytes)
	if err != nil {
		return nil, err
	}
	if len(pubBytes) > 0 {
		masterPK, err := UnmarshalSignMasterPublicKeyRaw(pubBytes)
		if err != nil {
			return nil, err
		}
		priv.internal.SetMasterPublicKey(masterPK.internal)
	}
	return priv, nil
}

// GenerateEncryptMasterKey generates an encryption master key pair.
func GenerateEncryptMasterKey(rand io.Reader) (*EncryptMasterPrivateKey, error) {
	priv, err := sm9.GenerateEncryptMasterKey(rand)
	if err != nil {
		return nil, err
	}
	master := &EncryptMasterPrivateKey{privateKey: priv.Bytes(), internal: priv}
	master.publicKey = &EncryptMasterPublicKey{publicKey: priv.PublicKey().Bytes(), internal: priv.PublicKey()}
	return master, nil
}

// Bytes returns the byte representation of the EncryptMasterPrivateKey.
// It delegates the call to the Bytes method of the underlying privateKey.
func (master *EncryptMasterPrivateKey) Bytes() []byte {
	var buf [32]byte
	return append(buf[:0], master.privateKey...)
}

// Equal compares the receiver EncryptMasterPrivateKey with another EncryptMasterPrivateKey
// and returns true if they are equal, otherwise it returns false.
func (master *EncryptMasterPrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*EncryptMasterPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(master.privateKey, xx.privateKey) == 1
}

// GenerateUserKey generate an encryption private key for the given user.
func (master *EncryptMasterPrivateKey) GenerateUserKey(uid []byte, hid byte) (*EncryptPrivateKey, error) {
	priv, err := master.internal.GenerateUserKey(uid, hid)
	if err != nil {
		return nil, err
	}
	return &EncryptPrivateKey{privateKey: priv.Bytes(), internal: priv}, nil
}

// Public returns the public key corresponding to the private key.
func (master *EncryptMasterPrivateKey) PublicKey() *EncryptMasterPublicKey {
	return master.publicKey
}

func (master *EncryptMasterPrivateKey) Public() crypto.PublicKey {
	return master.PublicKey()
}

// MarshalASN1 marshal encryption master private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (master *EncryptMasterPrivateKey) MarshalASN1() ([]byte, error) {
	d := new(big.Int).SetBytes(master.privateKey)
	var b cryptobyte.Builder
	b.AddASN1BigInt(d)
	return b.Bytes()
}

// UnmarshalEncryptMasterPrivateKeyASN1 unmarsal der data to master encryption private key
func UnmarshalEncryptMasterPrivateKeyASN1(der []byte) (*EncryptMasterPrivateKey, error) {
	input := cryptobyte.String(der)
	d := &big.Int{}
	var inner cryptobyte.String
	var pubBytes []byte
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1Integer(d) {
			return nil, errors.New("sm9: invalid ASN.1 data for encryption master private key")
		}
		// Just parse it, did't validate it
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return nil, errors.New("sm9: invalid ASN.1 data for encryption master public key")
		}
	} else if !input.ReadASN1Integer(d) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for encryption master private key")
	}
	privateKey, err := sm9.NewEncryptMasterPrivateKey(d.Bytes())
	if err != nil {
		return nil, err
	}

	master := &EncryptMasterPrivateKey{privateKey: privateKey.Bytes(), internal: privateKey}
	master.publicKey = &EncryptMasterPublicKey{
		publicKey: privateKey.PublicKey().Bytes(),
		internal:  privateKey.PublicKey(),
	}
	return master, nil
}

// Equal compares the receiver EncryptMasterPublicKey with another EncryptMasterPublicKey
// and returns true if they are equal, otherwise it returns false.
func (pub *EncryptMasterPublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*EncryptMasterPublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(pub.publicKey, xx.publicKey) == 1
}

// Bytes returns the byte representation of the EncryptMasterPublicKey.
// It delegates the call to the Bytes method of the underlying publicKey.
func (pub *EncryptMasterPublicKey) Bytes() []byte {
	var buf [65]byte
	return append(buf[:0], pub.publicKey...)
}

// MarshalASN1 marshal encryption master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (pub *EncryptMasterPublicKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.publicKey)
	return b.Bytes()
}

// MarshalCompressedASN1 marshal encryption master public key to asn.1 format data according
// SM9 cryptographic algorithm application specification, the curve point is in compressed form.
func (pub *EncryptMasterPublicKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(pub.publicKey)
	return b.Bytes()
}

// UnmarshalEncryptMasterPublicKeyRaw unmarsal raw bytes data to encryption master public key
func UnmarshalEncryptMasterPublicKeyRaw(bytes []byte) (*EncryptMasterPublicKey, error) {
	pub := new(EncryptMasterPublicKey)
	pub.internal = new(sm9.EncryptMasterPublicKey)
	err := pub.internal.UnmarshalRaw(bytes)
	if err != nil {
		return nil, err
	}
	pub.publicKey = pub.internal.Bytes()
	return pub, nil
}

// ParseEncryptMasterPublicKeyPEM just for GMSSL, there are no Algorithm pkix.AlgorithmIdentifier
func ParseEncryptMasterPublicKeyPEM(data []byte) (*EncryptMasterPublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("sm9: failed to parse PEM block")
	}
	return UnmarshalEncryptMasterPublicKeyASN1(block.Bytes)
}

// UnmarshalEncryptMasterPublicKeyASN1 unmarsal der data to encryption master public key
func UnmarshalEncryptMasterPublicKeyASN1(der []byte) (*EncryptMasterPublicKey, error) {
	var bytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) ||
			!inner.Empty() {
			return nil, errors.New("sm9: invalid ASN.1 data for encryption master public key")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for encryption master public key")
	}
	return UnmarshalEncryptMasterPublicKeyRaw(bytes)
}

// MasterPublic returns the master public key corresponding to priv.
func (priv *EncryptPrivateKey) MasterPublic() *EncryptMasterPublicKey {
	master := priv.internal.MasterPublic()
	return &EncryptMasterPublicKey{publicKey: master.Bytes(), internal: master}
}

// MarshalASN1 marshal encryption private key to asn.1 format data according
// SM9 cryptographic algorithm application specification
func (priv *EncryptPrivateKey) MarshalASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.privateKey)
	return b.Bytes()
}

// MarshalCompressedASN1 marshal encryption private key to asn.1 format data according
// SM9 cryptographic algorithm application specification, the curve point is in compressed form.
func (priv *EncryptPrivateKey) MarshalCompressedASN1() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1BitString(priv.privateKey)
	return b.Bytes()
}

// UnmarshalEncryptPrivateKeyRaw unmarsal raw bytes data to encryption private key
// Note, priv's EncryptMasterPublicKey should be handled separately.
func UnmarshalEncryptPrivateKeyRaw(bytes []byte) (*EncryptPrivateKey, error) {
	priv := new(EncryptPrivateKey)
	priv.internal = new(sm9.EncryptPrivateKey)
	err := priv.internal.UnmarshalRaw(bytes)
	if err != nil {
		return nil, err
	}
	priv.privateKey = priv.internal.Bytes()
	return priv, nil
}

// UnmarshalEncryptPrivateKeyASN1 unmarsal der data to encryption private key
// Note, priv's EncryptMasterPublicKey should be handled separately.
func UnmarshalEncryptPrivateKeyASN1(der []byte) (*EncryptPrivateKey, error) {
	var bytes []byte
	var pubBytes []byte
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if der[0] == 0x30 {
		if !input.ReadASN1(&inner, cryptobyte_asn1.SEQUENCE) ||
			!input.Empty() ||
			!inner.ReadASN1BitStringAsBytes(&bytes) {
			return nil, errors.New("sm9: invalid ASN.1 data for encryption private key")
		}
		if !inner.Empty() && (!inner.ReadASN1BitStringAsBytes(&pubBytes) || !inner.Empty()) {
			return nil, errors.New("sm9: invalid ASN.1 data for encryption master public key")
		}
	} else if !input.ReadASN1BitStringAsBytes(&bytes) || !input.Empty() {
		return nil, errors.New("sm9: invalid ASN.1 data for encryption private key")
	}
	priv, err := UnmarshalEncryptPrivateKeyRaw(bytes)
	if err != nil {
		return nil, err
	}
	if len(pubBytes) > 0 {
		masterPK, err := UnmarshalEncryptMasterPublicKeyRaw(pubBytes)
		if err != nil {
			return nil, err
		}
		priv.internal.SetMasterPublicKey(masterPK.internal)
	}
	return priv, nil
}

// Equal compares the receiver EncryptPrivateKey with another EncryptPrivateKey x
// and returns true if they are equal, otherwise false.
func (priv *EncryptPrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*EncryptPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(priv.privateKey, xx.privateKey) == 1
}

// Public returns the public key corresponding to the private key.
// Just to satisfy [crypto.Decrypter] interface.
func (priv *EncryptPrivateKey) Public() crypto.PublicKey {
	return nil
}

// Bytes returns the byte representation of the EncryptPrivateKey.
// It delegates the call to the Bytes method of the underlying privateKey.
func (priv *EncryptPrivateKey) Bytes() []byte {
	var buf [129]byte
	return append(buf[:0], priv.privateKey...)
}
