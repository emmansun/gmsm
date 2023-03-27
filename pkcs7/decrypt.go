package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
	"github.com/emmansun/gmsm/smx509"
)

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, SM2, DES, DES-EDE3, AES and SM4 supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is NOT a decryptable data type")

type decryptable interface {
	GetRecipient(cert *smx509.Certificate) *recipientInfo
	GetEncryptedContentInfo() *encryptedContentInfo
}

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *smx509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
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
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
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
