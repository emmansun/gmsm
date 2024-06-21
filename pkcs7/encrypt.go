package pkcs7

import (
	"encoding/asn1"
	"errors"

	"github.com/emmansun/gmsm/pkcs"
)

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(cipher pkcs.Cipher, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(cipher, content, key, []asn1.ObjectIdentifier{OIDData, OIDEncryptedData}, 0)
}

// EncryptSMUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
// This method uses China Standard OID
func EncryptSMUsingPSK(cipher pkcs.Cipher, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(cipher, content, key, []asn1.ObjectIdentifier{SM2OIDData, SM2OIDEncryptedData}, 1)
}

func encryptUsingPSK(cipher pkcs.Cipher, content []byte, key []byte, contentTypes []asn1.ObjectIdentifier, version int) ([]byte, error) {
	var err error

	if key == nil {
		return nil, ErrPSKNotProvided
	}

	id, ciphertext, err := cipher.Encrypt(key, content)
	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version:              version,
		EncryptedContentInfo: newEncryptedContent(contentTypes[0], id, marshalEncryptedContent(ciphertext)),
	}

	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: contentTypes[1],
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}
