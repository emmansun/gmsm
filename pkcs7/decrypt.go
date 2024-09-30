package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// IssuerAndSerial is a structure that holds the issuer name and serial number
type IssuerAndSerial struct {
	RawIssuer   []byte
	SerialNumber *big.Int
}

func newIssuerAndSerial(issuerAndSerial issuerAndSerial) IssuerAndSerial {
	is := IssuerAndSerial{}
	if len(issuerAndSerial.IssuerName.FullBytes) > 0 {
		is.RawIssuer = make([]byte, len(issuerAndSerial.IssuerName.FullBytes))
		copy(is.RawIssuer, issuerAndSerial.IssuerName.FullBytes)
	}
	if issuerAndSerial.SerialNumber != nil {
		is.SerialNumber = new(big.Int).Set(issuerAndSerial.SerialNumber)
	}
	return is
}

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, SM2, DES, DES-EDE3, AES and SM4 supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is NOT a decryptable data type")

// ErrNotEnvelopedData is returned when attempting to Decrypt data that is not enveloped data
var ErrNotEnvelopedData = errors.New("pkcs7: content data is NOT an enveloped data type")

type decryptable interface {
	GetRecipient(cert *smx509.Certificate) *recipientInfo
	GetRecipients() ([]IssuerAndSerial, error)
	GetEncryptedContentInfo() *encryptedContentInfo
}

// GetRecipients returns the list of recipients for the enveloped data
func (p7 *PKCS7) GetRecipients() ([]IssuerAndSerial, error) {
	decryptableData, ok := p7.raw.(decryptable)
	if !ok {
		return nil, ErrNotEnvelopedData
	}
	return decryptableData.GetRecipients()
}

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *smx509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	return p7.decrypt(cert, pkey, false)
}

// DecryptCFCA decrypts encrypted content info for recipient cert and private key whose SM2 encrypted key is C1C2C3 format
// and without 0x4 prefix.
func (p7 *PKCS7) DecryptCFCA(cert *smx509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	return p7.decrypt(cert, pkey, true)
}

func (p7 *PKCS7) decrypt(cert *smx509.Certificate, pkey crypto.PrivateKey, isCFCA bool) ([]byte, error) {
	decryptableData, ok := p7.raw.(decryptable)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := decryptableData.GetRecipient(cert)
	if recipient == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}

	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		// Generic case to handle anything that provides the crypto.Decrypter interface.
		encryptedKey := recipient.EncryptedKey
		var decrypterOpts crypto.DecrypterOpts
		if _, ok := pkey.(*sm2.PrivateKey); ok && isCFCA {
			encryptedKey = make([]byte, len(recipient.EncryptedKey)+1)
			encryptedKey[0] = 0x04
			copy(encryptedKey[1:], recipient.EncryptedKey)
			decrypterOpts = sm2.NewPlainDecrypterOpts(sm2.C1C2C3)
		}

		contentKey, err := pkey.Decrypt(rand.Reader, encryptedKey, decrypterOpts)
		if err != nil {
			return nil, err
		}
		return decryptableData.GetEncryptedContentInfo().decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) getCiphertext() (ciphertext []byte) {
	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		ciphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		ciphertext = eci.EncryptedContent.Bytes
	}
	return
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	cipher, err := pkcs.GetCipher(eci.ContentEncryptionAlgorithm)
	if err != nil {
		return nil, ErrUnsupportedAlgorithm
	}
	return cipher.Decrypt(key, &eci.ContentEncryptionAlgorithm.Parameters, eci.getCiphertext())
}
