# SM2 Elliptic Curve Public Key Cryptography Algorithm - Application Guide

## Table of Contents
- [Standards and References](#standards-and-references)
- [Overview](#overview)
- [Key Pair Management](#key-pair-management)
- [Digital Signature](#digital-signature)
- [Key Exchange Protocol](#key-exchange-protocol)
- [Public Key Encryption](#public-key-encryption)
- [KMS Integration](#kms-integration)
- [Hardware Cryptographic Module Integration](#hardware-cryptographic-module-integration)
- [Advanced Applications](#advanced-applications)

---

## Standards and References

### National Standards (GB/T)
- **GB/T 32918.1-2016** - Information Security Technology - SM2 Elliptic Curve Public Key Cryptographic Algorithm - Part 1: General
- **GB/T 32918.2-2016** - Information Security Technology - SM2 Elliptic Curve Public Key Cryptographic Algorithm - Part 2: Digital Signature Algorithm
- **GB/T 32918.3-2016** - Information Security Technology - SM2 Elliptic Curve Public Key Cryptographic Algorithm - Part 3: Key Exchange Protocol
- **GB/T 32918.4-2016** - Information Security Technology - SM2 Elliptic Curve Public Key Cryptographic Algorithm - Part 4: Public Key Encryption Algorithm
- **GB/T 32918.5-2017** - Information Security Technology - SM2 Elliptic Curve Public Key Cryptographic Algorithm - Part 5: Parameter Definition
- **GB/T 35276-2017** - Information Security Technology - SM2 Cryptographic Algorithm Application Specification
- **GB/T 33560-2017** - Information Security Technology - Cryptographic Application Identifier Specification
- **GB/T 35275-2017** - Information Security Technology - SM2 Cryptographic Algorithm Encrypted Signature Message Syntax Specification (PKCS#7 Equivalent)

### Industry Standards (GM/T)
- **GM/T 0091-2020** - Password-Based Key Derivation Specification
- **GM/T 0092-2020** - Certificate Application Syntax Specification Based on SM2 Algorithm

### Related Standards
- **GB/T 36322-2018** - Application Interface Specification for Cryptographic Devices (SDF API)
- **GB/T 35291-2017** - Application Interface Specification for Smart Cryptographic Key (SKF API)

> 📖 **Note:** Standards are available at the [National Standards Full-Text Disclosure System](https://openstd.samr.gov.cn/).

---

## Overview

### Algorithm Comparison

SM2 is an elliptic curve public key cryptographic algorithm similar to NIST P-series curves, particularly P-256. While NIST primarily standardized ECDSA for signatures and ECDH for key exchange, SM2 provides a comprehensive suite including public key encryption. The following table compares SM2 with international standards:

| **Functionality** | **SM2** | **NIST/SEC 1** |
|-------------------|---------|----------------|
| Digital Signature | SM2 Signature | ECDSA ([SEC 1](https://www.secg.org/sec1-v2.pdf)) |
| Key Exchange | SM2 Key Exchange | ECMQV ([SEC 1](https://www.secg.org/sec1-v2.pdf)) |
| Public Key Encryption | SM2 Encryption | ECIES ([SEC 1](https://www.secg.org/sec1-v2.pdf) Section 5) |

**Key Differences:**
- **SM2 Signature**: Incorporates user identifier (UID) in the hash computation (Z value calculation)
- **SM2 Encryption**: Uses SM3 hash for KDF, different MAC scheme compared to ECIES
- **SM2 Key Exchange**: Modified MQV protocol with identity-based components

### Security Context

The industry is experiencing increasing concerns about RSA asymmetric encryption security. Elliptic curve cryptography offers better security margins with smaller key sizes:

- 🔒 [The Marvin Attack](https://people.redhat.com/~hkario/marvin/) - Timing attack on RSA PKCS#1 v1.5
- 🔒 [CVE-2023-45287](https://nvd.nist.gov/vuln/detail/CVE-2023-45287) - RSA implementation vulnerability
- 🔒 [GO-2023-2375](https://pkg.go.dev/vuln/GO-2023-2375) - Go RSA vulnerability report
- 📄 [Trail of Bits: Stop Using RSA](https://blog.trailofbits.com/2019/07/08/fuck-rsa/) - Industry position paper

> ⚠️ **Best Practice:** Modern applications should prefer elliptic curve cryptography (ECC) over RSA for new implementations due to better security margins, smaller key sizes, and improved performance.

---

## Key Pair Management

### Key Pair Generation

Generate SM2 key pairs using the `sm2.GenerateKey()` function:

```go
import (
    "crypto/rand"
    "github.com/emmansun/gmsm/sm2"
)

// Generate a new SM2 key pair
priv, err := sm2.GenerateKey(rand.Reader)
if err != nil {
    log.Fatalf("Failed to generate key pair: %v", err)
}
```

**Key Type Structure:**

The SM2 private key extends `ecdsa.PrivateKey` to implement SM2-specific methods:

```go
// PrivateKey represents an ECDSA SM2 private key.
// It implements both crypto.Decrypter and crypto.Signer interfaces.
type PrivateKey struct {
    ecdsa.PrivateKey
    // Additional SM2-specific fields
}
```

The SM2 public key uses the standard `ecdsa.PublicKey` structure.

> ⚠️ **Important:** Since Go v1.20, `ecdsa.PublicKey` includes an `ECDH()` method that is **NOT** compatible with SM2. For SM2 keys, use `sm2.PublicKeyToECDH()` instead.

---

### Public Key Parsing and Construction

#### From PEM-Encoded Data

Public keys are typically transmitted as PEM-encoded text:

```go
import (
    "encoding/pem"
    "github.com/emmansun/gmsm/smx509"
)

func parsePublicKey(pemContent []byte) (*ecdsa.PublicKey, error) {
    block, _ := pem.Decode(pemContent)
    if block == nil {
        return nil, errors.New("failed to parse PEM block")
    }
    
    pub, err := smx509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    
    // Type assertion to *ecdsa.PublicKey
    ecdsaPub, ok := pub.(*ecdsa.PublicKey)
    if !ok {
        return nil, errors.New("not an ECDSA public key")
    }
    
    return ecdsaPub, nil
}
```

#### From Raw Coordinates

Construct a public key from uncompressed point coordinates:

```go
func ExampleNewPublicKey() {
    // Uncompressed point: 0x04 || X || Y
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    
    pub, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("Failed to create public key: %v", err)
    }
    
    // Verify by marshaling back
    marshaled := elliptic.Marshal(sm2.P256(), pub.X, pub.Y)
    fmt.Printf("%x\n", marshaled)
    // Output: 048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1
}
```

**Alternative Methods:**
- `ecdh.P256().NewPublicKey()` - Only supports uncompressed format
- Direct coordinate construction with `sm2.P256()` curve

---

### Private Key Parsing and Construction

#### Supported Encapsulation Formats

Private keys can be encapsulated in various formats. The appropriate parsing method depends on the format ([detailed discussion](https://github.com/emmansun/gmsm/issues/104)):

| **Format** | **Parsing Method** | **Description** |
|------------|-------------------|-----------------|
| **RFC 5915 / SEC1** | `smx509.ParseSM2PrivateKey()` | Standard EC private key format |
| **PKCS#8 (Unencrypted)** | `smx509.ParsePKCS8PrivateKey()` | Standard unencrypted private key |
| **PKCS#8 (Encrypted)** | `pkcs8.ParsePKCS8PrivateKeySM2()` | Handles both encrypted and unencrypted |
| **PKCS#12** | `github.com/emmansun/go-pkcs12` | Microsoft PFX format |
| **PKCS#7 / CMS** | `github.com/emmansun/gmsm/pkcs7` | Cryptographic Message Syntax |
| **CFCA Custom** | `cfca.ParseSM2()` | CFCA-specific PKCS#12 variant |
| **GB/T 35276-2017** | `sm2.ParseEnvelopedPrivateKey()` | Enveloped private key (CSR response) |

> 📝 **Note:** PEM files typically indicate the format in the first line (e.g., `-----BEGIN EC PRIVATE KEY-----`). ASN.1-encoded keys require OID inspection for format identification.

#### Parsing Examples

**PKCS#8 Encrypted Private Key:**

```go
import (
    "github.com/emmansun/gmsm/pkcs8"
)

func parseEncryptedPrivateKey(pemData []byte, password []byte) (*sm2.PrivateKey, error) {
    block, _ := pem.Decode(pemData)
    if block == nil {
        return nil, errors.New("failed to decode PEM")
    }
    
    priv, err := pkcs8.ParsePKCS8PrivateKeySM2(block.Bytes, password)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %w", err)
    }
    
    return priv, nil
}
```

**GB/T 35276-2017 Enveloped Private Key:**

Typical use case: CA certificate response containing signing certificate, CA-generated encryption private key, and encryption certificate:

```go
import (
    "github.com/emmansun/gmsm/sm2"
)

func parseEnvelopedPrivateKey(envelopedData []byte, decryptKey *sm2.PrivateKey) (*sm2.PrivateKey, error) {
    priv, err := sm2.ParseEnvelopedPrivateKey(envelopedData, decryptKey)
    if err != nil {
        return nil, fmt.Errorf("failed to parse enveloped key: %w", err)
    }
    return priv, nil
}
```

#### From Raw Bytes

Construct a private key directly from scalar bytes:

```go
func ExampleNewPrivateKey() {
    // Private key as 32-byte scalar
    keyBytes, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    
    priv, err := sm2.NewPrivateKey(keyBytes)
    if err != nil {
        log.Fatalf("Failed to create private key: %v", err)
    }
    
    fmt.Printf("%x\n", priv.D.Bytes())
    // Output: 6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85
}

func ExampleNewPrivateKeyFromInt() {
    key := big.NewInt(0x123456)
    priv, err := sm2.NewPrivateKeyFromInt(key)
    if err != nil {
        log.Fatalf("Failed to create private key: %v", err)
    }
    
    fmt.Printf("%x\n", priv.D.Bytes())
    // Output: 123456
}
```

**Alternative Methods:**
- `ecdh.P256().NewPrivateKey()` - Requires exactly 32 bytes (zero-pad if necessary)

---

### GM/T 0091-2020: Password-Based Key Derivation

**GM/T 0091-2020** is essentially a Chinese customization of [RFC 8018 (PKCS#5)](https://datatracker.ietf.org/doc/html/rfc8018) with different OIDs for PBES/PBKDF/PBMAC schemes. However, these OIDs appear unregistered, and there are inconsistencies within the standard itself.

#### OID Definitions

| **Object Identifier** | **Definition** |
|----------------------|----------------|
| `1.2.156.10197.6.1.4.1.5` | Password-Based Key Derivation Specification |
| `1.2.156.10197.6.1.4.1.5.1` | PBKDF (essentially PBKDF2) |
| `1.2.156.10197.6.1.4.1.5.2` | PBES (essentially PBES2) |
| `1.2.156.10197.6.1.4.1.5.3` | PBMAC (Password-Based MAC) |

#### Standard Inconsistencies

1. **Appendix A.2** defines `id-hmacWithSM3` as `1.2.156.10197.1.401.3.1` (unregistered)
2. **Appendix A.4** example fragment uses OID `1.2.156.10197.1.401`, suggesting copy-paste from PKCS#12-MAC instead of PBMAC1
3. **Appendix B.2** introduces `pbeWithSM3AndSM4-CBC` as `1.2.156.10197.6.1.4.1.12.1.1` (suggests PBES1 approach)
4. **Appendix C** redefines `id-hmacWithSM3` as `1.2.156.10197.1.401.2` (contradicts A.2)

> ⚠️ **Compatibility Warning:** Due to these inconsistencies, interoperability with products claiming GM/T 0091-2020 compliance may be challenging. The commonly used `id-hmacWithSM3` OID is `1.2.156.10197.1.401.2`.

---

## Digital Signature

### Standard Signing

SM2 signatures incorporate a user identifier (UID) in the hash computation through the **Z** value. The standard UID is `1234567812345678@` (default).

#### Basic Signing Example

```go
func ExamplePrivateKey_Sign() {
    toSign := []byte("ShangMi SM2 Sign Standard")
    
    // Load or generate private key
    privKey, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    testkey, err := sm2.NewPrivateKey(privKey)
    if err != nil {
        log.Fatalf("Failed to create private key: %v", err)
    }

    // Sign with default SM2 options (includes Z value calculation)
    sig, err := testkey.Sign(rand.Reader, toSign, sm2.DefaultSM2SignerOpts)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
        return
    }

    fmt.Printf("Signature: %x\n", sig)
}
```

#### Custom UID Signing

For non-standard UIDs, create custom signer options:

```go
import "github.com/emmansun/gmsm/sm2"

customUID := []byte("customUserID@domain.com")
signerOpts := sm2.NewSM2SignerOption(true, customUID)

sig, err := privateKey.Sign(rand.Reader, message, signerOpts)
```

#### SM2-Specific Signing Method

Use the `SignWithSM2` method from the `sm2.Signer` interface for explicit SM2 signing:

```go
sig, err := privateKey.SignWithSM2(rand.Reader, uid, message)
```

**Interface Comparison:**
- `Sign()` - From `crypto.Signer` interface (standard Go crypto)
- `SignWithSM2()` - From `sm2.Signer` interface (SM2-specific)

---

### Signature Verification

Verify SM2 signatures using `sm2.VerifyASN1WithSM2()`:

```go
func ExampleVerifyASN1WithSM2() {
    // Parse or construct public key
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    publicKey, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("Failed to create public key: %v", err)
    }

    message := []byte("ShangMi SM2 Sign Standard")
    signature, _ := hex.DecodeString(
        "304402205b3a799bd94c9063120d7286769220af6b0fa127009af3e873c0e8742edc5f89" +
        "0220097968a4c8b040fd548d1456b33f470cabd8456bfea53e8a828f92f6d4bdcd77")

    // Verify with default UID (nil = use default)
    valid := sm2.VerifyASN1WithSM2(publicKey, nil, message, signature)

    fmt.Printf("Signature valid: %v\n", valid)
    // Output: Signature valid: true
}
```

**Custom UID Verification:**

```go
customUID := []byte("customUserID@domain.com")
valid := sm2.VerifyASN1WithSM2(publicKey, customUID, message, signature)
```

---

### Signing Without Z Value

For compatibility with systems expecting ECDSA-style signatures (no Z value computation):

#### Signing

```go
// Pre-compute hash yourself
hash := sm3.Sum(message)

// Sign the hash directly (no Z value)
sig, err := privateKey.Sign(rand.Reader, hash[:], nil)
```

> 📝 **Note:** When `SignerOpts` is `nil` or not `SM2SignerOption`, the input is treated as a pre-computed hash without Z value computation.

#### Verification

```go
// Pre-compute hash yourself (must match signing hash algorithm)
hash := sm3.Sum(message)

// Verify without Z value
valid := sm2.VerifyASN1(publicKey, hash[:], signature)
```

> ⚠️ **Important:** Ensure the hash algorithm used for signing and verification are identical.

---

### Large File Signing

For large files, sign the hash instead of the entire file:

```go
import (
    "github.com/emmansun/gmsm/sm3"
    "io"
)

func signLargeFile(file io.Reader, privateKey *sm2.PrivateKey, uid []byte) ([]byte, error) {
    // Calculate Z value
    za, err := sm2.CalculateZA(privateKey.Public().(*ecdsa.PublicKey), uid)
    if err != nil {
        return nil, err
    }
    
    // Hash the file with Z value prepended
    h := sm3.New()
    h.Write(za)
    if _, err := io.Copy(h, file); err != nil {
        return nil, err
    }
    hash := h.Sum(nil)
    
    // Sign the hash
    return privateKey.Sign(rand.Reader, hash, nil)
}
```

> 💡 **Tip:** Since v0.24.0, use `sm2.CalculateSM2Hash()` for convenient hash computation with Z value.

---

## Key Exchange Protocol

SM2 key exchange protocol implementations are available in two packages:

### Implementation Comparison

| **Package** | **Description** | **Use Case** |
|-------------|----------------|--------------|
| `sm2` | Traditional implementation | Legacy compatibility |
| `ecdh` | Modern Go-style implementation | New applications, TLS/TLCP |

Both implementations provide secure key agreement functionality. The `ecdh` package follows Go's modern cryptographic API design patterns.

> 📖 **Reference:** For practical usage examples, see the [gotlcp](https://github.com/Trisia/gotlcp) TLS/TLCP implementation.

> ⚠️ **Note:** Key exchange protocols are primarily used in TLS/TLCP contexts. Most application-level development does not require direct use of key exchange protocols.

---

## Public Key Encryption

### Overview

> ⚠️ **Important Principle:** Asymmetric encryption is NOT designed for encrypting large amounts of data. It should be used to encrypt symmetric keys, which then encrypt the actual data. This pattern is used in:
> - **TLS/TLCP**: Encrypting session keys
> - **Envelope Encryption**: Encrypting data encryption keys (DEKs)

### Ciphertext Encoding Formats

SM2 public key encryption supports two ciphertext formats:

| **Format** | **Description** | **Structure** |
|------------|----------------|---------------|
| **ASN.1** | Standard encoding | ASN.1 DER structure |
| **Plain Concatenation** | Simple byte concatenation | C1‖C3‖C2 (current standard) or C1‖C2‖C3 (legacy) |

**Format Components:**
- **C1**: Ephemeral public key point (elliptic curve point)
- **C2**: Encrypted message
- **C3**: Message authentication code (MAC)

> 📝 **Historical Note:** The 2010 standard used C1‖C2‖C3 format. The 2012 standard (GM/T 0003-2012) changed to C1‖C3‖C2, which has been maintained through GB/T 32918-2016.

---

### Encryption

#### ASN.1 Format Encryption

```go
func ExampleEncryptASN1() {
    // Parse or load public key
    keypoints, _ := hex.DecodeString(
        "048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988" +
        "981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1")
    publicKey, err := sm2.NewPublicKey(keypoints)
    if err != nil {
        log.Fatalf("Failed to create public key: %v", err)
    }

    plaintext := []byte("send reinforcements, we're going to advance")

    // Encrypt using ASN.1 format
    ciphertext, err := sm2.EncryptASN1(rand.Reader, publicKey, plaintext)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Encryption error: %s\n", err)
        return
    }

    fmt.Printf("Ciphertext (ASN.1): %x\n", ciphertext)
}
```

#### Plain Concatenation Format Encryption

```go
// Encrypt with plain concatenation (default C1C3C2)
ciphertext, err := sm2.Encrypt(rand.Reader, publicKey, plaintext, nil)
if err != nil {
    fmt.Fprintf(os.Stderr, "Encryption error: %s\n", err)
    return
}

fmt.Printf("Ciphertext (C1C3C2): %x\n", ciphertext)
```

> 📝 **Note:** Passing `nil` as `EncrypterOpts` defaults to C1‖C3‖C2 format.

---

### Decryption

The SM2 private key's `Decrypt()` method automatically detects the ciphertext format:

```go
func ExamplePrivateKey_Decrypt() {
    ciphertext, _ := hex.DecodeString(
        "308194022100bd31001ce8d39a4a0119ff96d71334cd12d8b75bbc780f5bfc6e1efab535e85a" +
        "02201839c075ff8bf761dcbe185c9750816410517001d6a130f6ab97fb23337cce1504" +
        "20ea82bd58d6a5394eb468a769ab48b6a26870ca075377eb06663780c920ea5ee00" +
        "42be22abcf48e56ae9d29ac770d9de0d6b7094a874a2f8d26c26e0b1daaf4ff50a484b88163d04785b04585bb")

    // Load private key
    privKey, _ := hex.DecodeString(
        "6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85")
    privateKey, err := sm2.NewPrivateKey(privKey)
    if err != nil {
        log.Fatalf("Failed to create private key: %v", err)
    }

    // Decrypt (auto-detects ASN.1 or C1C3C2 format)
    plaintext, err := privateKey.Decrypt(nil, ciphertext, nil)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Decryption error: %s\n", err)
        return
    }

    fmt.Printf("Plaintext: %s\n", string(plaintext))
    // Output: Plaintext: send reinforcements, we're going to advance
}
```

**Legacy C1C2C3 Format:**

For legacy C1‖C2‖C3 ciphertext, specify the format explicitly:

```go
import "github.com/emmansun/gmsm/sm2"

// Specify C1C2C3 format
opts := &sm2.DecrypterOpts{
    CiphertextEncoding: sm2.C1C2C3,
}

plaintext, err := privateKey.Decrypt(nil, ciphertext, opts)
```

**Alternative:** Convert ciphertext format before decryption using helper functions.

---

### Ciphertext Format Conversion

The `sm2` package provides utility functions for format conversion:

#### ASN.1 ↔ Plain Concatenation

```go
import "github.com/emmansun/gmsm/sm2"

// ASN.1 to plain concatenation (C1C3C2)
plainCiphertext, err := sm2.ASN1Ciphertext2Plain(asn1Ciphertext, nil)

// Plain concatenation to ASN.1
asn1Ciphertext, err := sm2.PlainCiphertext2ASN1(plainCiphertext, sm2.C1C3C2)
```

#### Change Concatenation Order

```go
// Convert between C1C2C3 and C1C3C2
convertedCiphertext, err := sm2.AdjustCiphertextSplicingOrder(
    ciphertext,
    sm2.C1C2C3, // Source format
    sm2.C1C3C2, // Target format
)
```

---

### Technical Background

#### Point-to-Octet-String Conversion

All SM2 standards (from the 2010 Cryptography Administration version through GB/T 32918-2016) consistently define point-to-octet-string conversion in Part 1, Chapter 4. This follows [SEC 1: Elliptic Curve Cryptography (Version 2.0)](https://www.secg.org/sec1-v2.pdf) Section 2.3.3 specifications.

**Standard Formats:**
- **Uncompressed**: `0x04 || X || Y` (65 bytes for SM2)
- **Compressed**: `0x02 || X` or `0x03 || X` (33 bytes for SM2)
- **Hybrid** (rare): `0x06 || X || Y` or `0x07 || X || Y`

> ⚠️ **Clarification:** Some implementations use fixed 64-byte representation (omitting the format indicator). This is **non-standard** and causes interoperability issues. Always follow SEC 1 specifications for proper encoding.

#### Why Some Implementations Omit Format Indicators

**Reasons for omission:**
1. **Simplicity**: Reduces implementation complexity
2. **Assumed Knowledge**: All points in a closed system use the same format
3. **Legacy Compatibility**: Older systems may not support multiple formats
4. **Misunderstanding**: Incorrect interpretation of standards

**Consequences:**
- ❌ **Breaks Interoperability**: Systems expecting format indicators cannot parse the data
- ❌ **Security Risk**: Ambiguity in point representation can lead to validation failures
- ❌ **Non-Compliance**: Violates SEC 1 and GB/T 32918 standards

> ✅ **Best Practice:** Always include format indicators as specified in SEC 1. For maximum compatibility, use uncompressed format (`0x04`) with proper encoding.

---

### Performance Optimization

Since **v0.27.0**, significant performance improvements have been implemented for large data encryption/decryption:

**Optimizations:**
- ✅ Parallel KDF computation for key derivation
- ✅ Optimized hash operations
- ✅ Improved memory allocation strategies

For detailed benchmarks and performance analysis, refer to [SM2 Encryption/Decryption Performance](https://github.com/emmansun/gmsm/wiki/SM2%E5%8A%A0%E8%A7%A3%E5%AF%86%E6%80%A7%E8%83%BD).

> 📊 **Performance Tip:** For encrypting large amounts of data, use envelope encryption (SM2 encrypts a symmetric key, then use SM4 to encrypt the actual data).

---

## KMS Integration

### Overview

Major cloud service providers in China offer SM2 key management services. Typical integration patterns:

| **Operation** | **Location** | **Key Type** |
|--------------|-------------|--------------|
| **Signing** | KMS API call | Private key (in KMS) |
| **Verification** | Local | Public key |
| **Encryption** | Local | Public key |
| **Decryption** | KMS API call | Private key (in KMS) |

### Hash Calculation for KMS Signing

Most KMS services require pre-hashed data for signing. SM2 signatures require special hash computation including the **Z** value:

#### Calculate SM2 Hash

```go
import (
    "github.com/emmansun/gmsm/sm2"
    "github.com/emmansun/gmsm/sm3"
)

func calculateSM2HashForKMS(pub *ecdsa.PublicKey, data, uid []byte) ([]byte, error) {
    // Use default UID if not specified
    if len(uid) == 0 {
        uid = []byte("1234567812345678")
    }
    
    // Calculate ZA (Z value)
    za, err := sm2.CalculateZA(pub, uid)
    if err != nil {
        return nil, err
    }
    
    // Hash: SM3(ZA || message)
    h := sm3.New()
    h.Write(za)
    h.Write(data)
    return h.Sum(nil), nil
}
```

> 💡 **Convenience Function:** Since v0.24.0, use `sm2.CalculateSM2Hash()` directly:

```go
hash, err := sm2.CalculateSM2Hash(publicKey, data, uid)
```

### KMS Encryption

Public key encryption is straightforward - ensure ciphertext encoding matches KMS requirements:

```go
// Most KMS services use ASN.1 format
ciphertext, err := sm2.EncryptASN1(rand.Reader, publicKey, plaintext)
if err != nil {
    return nil, fmt.Errorf("encryption failed: %w", err)
}

// Send ciphertext to KMS for decryption
```

### Best Practices for KMS Integration

1. **Cache Public Keys**: Retrieve public keys once and cache them locally
2. **Minimize KMS Calls**: Use KMS only for operations requiring private keys
3. **Error Handling**: Implement retry logic for transient KMS API failures
4. **Key Rotation**: Design systems to handle key rotation seamlessly
5. **Audit Logging**: Log all KMS operations for security auditing

---

## Hardware Cryptographic Module Integration

### Overview

Hardware cryptographic modules (HSMs) typically implement SDF (Security Device Framework) or SKF (Smart Key Framework) APIs. Private keys in HSMs are **non-exportable** but provide signing and decryption operations through APIs.

To integrate with GMSM library, implement the following Go crypto interfaces:

### Required Interfaces

#### 1. `crypto.Signer` Interface

```go
type Signer interface {
    // Public returns the public key corresponding to the private key
    Public() crypto.PublicKey
    
    // Sign signs digest with the private key
    // For SM2: digest is typically pre-computed hash or raw message
    Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
}
```

#### 2. `crypto.Decrypter` Interface

```go
type Decrypter interface {
    // Public returns the public key corresponding to the private key
    Public() crypto.PublicKey
    
    // Decrypt decrypts msg with the private key
    Decrypt(rand io.Reader, msg []byte, opts DecrypterOpts) (plaintext []byte, err error)
}
```

### Implementation Guidelines

#### Public() Method

```go
func (h *HSMPrivateKey) Public() crypto.PublicKey {
    // Return the public key associated with this private key
    // This should be retrieved from the HSM or stored during initialization
    return h.publicKey
}
```

#### Sign() Method

```go
func (h *HSMPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    // Check if opts is SM2-specific
    if sm2Opts, ok := opts.(*sm2.SM2SignerOption); ok && sm2Opts.ForceGMSign {
        // Treat digest as raw message, calculate SM2 hash
        hash, err := sm2.CalculateSM2Hash(
            h.Public().(*ecdsa.PublicKey),
            digest,
            sm2Opts.UID,
        )
        if err != nil {
            return nil, err
        }
        
        // Call HSM API to sign the hash
        return h.hsmSignHash(hash)
    }
    
    // Treat digest as pre-computed hash
    return h.hsmSignHash(digest)
}

func (h *HSMPrivateKey) hsmSignHash(hash []byte) ([]byte, error) {
    // Call SDF/SKF API to perform signing
    // Example: SDF_InternalSign_ECC(sessionHandle, keyIndex, hash)
    return h.sdkClient.Sign(h.keyHandle, hash)
}
```

**Important Considerations:**

1. **Hash Handling**: Most HSM APIs expect a hash value. For SM2:
   - If `opts` is `*sm2.SM2SignerOption`, calculate SM2 hash (including Z value)
   - Otherwise, use digest as-is (pre-computed hash)

2. **Random Number Source**: HSMs typically have hardware RNGs. The `rand` parameter may be ignored.

3. **Error Handling**: Map HSM-specific errors to Go error types.

#### Decrypt() Method

```go
func (h *HSMPrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    // Call SDF/SKF API to perform decryption
    // Example: SDF_InternalDecrypt_ECC(sessionHandle, keyIndex, ciphertext)
    
    plaintext, err := h.sdkClient.Decrypt(h.keyHandle, msg)
    if err != nil {
        return nil, fmt.Errorf("HSM decryption failed: %w", err)
    }
    
    return plaintext, nil
}
```

### Complete Example

```go
package hsm

import (
    "crypto"
    "crypto/ecdsa"
    "io"
    
    "github.com/emmansun/gmsm/sm2"
)

// HSMPrivateKey represents a private key stored in HSM
type HSMPrivateKey struct {
    keyHandle  int                // HSM key handle/index
    publicKey  *ecdsa.PublicKey   // Associated public key
    sdkClient  *SDFClient         // SDF/SKF SDK client
}

// Ensure interface compliance at compile time
var (
    _ crypto.Signer    = (*HSMPrivateKey)(nil)
    _ crypto.Decrypter = (*HSMPrivateKey)(nil)
)

func (h *HSMPrivateKey) Public() crypto.PublicKey {
    return h.publicKey
}

func (h *HSMPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
    var hash []byte
    
    // Check if this is SM2-specific signing
    if sm2Opts, ok := opts.(*sm2.SM2SignerOption); ok && sm2Opts.ForceGMSign {
        // Calculate SM2 hash (ZA || message)
        var err error
        hash, err = sm2.CalculateSM2Hash(h.publicKey, digest, sm2Opts.UID)
        if err != nil {
            return nil, err
        }
    } else {
        // Use digest as-is (assumed to be pre-computed hash)
        hash = digest
    }
    
    // Call HSM signing function
    signature, err := h.sdkClient.InternalSign(h.keyHandle, hash)
    if err != nil {
        return nil, err
    }
    
    return signature, nil
}

func (h *HSMPrivateKey) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
    plaintext, err := h.sdkClient.InternalDecrypt(h.keyHandle, msg)
    if err != nil {
        return nil, err
    }
    
    return plaintext, nil
}
```

### SDF/SKF API References

**SDF (GB/T 36322-2018)**: Security Device Framework
- `SDF_OpenDevice` - Open device session
- `SDF_InternalSign_ECC` - Internal key signing
- `SDF_InternalDecrypt_ECC` - Internal key decryption
- `SDF_ExportSignPublicKey_ECC` - Export public key

**SKF (GB/T 35291-2017)**: Smart Key Framework  
- `SKF_ConnectDev` - Connect to device
- `SKF_ECCSignData` - Sign data with ECC key
- `SKF_DecryptData` - Decrypt data

> 📖 **Standards**: Refer to GB/T 36322-2018 (Cryptographic Device Application Interface Specification) for complete SDF API documentation.

---

## Advanced Applications

SM2 elliptic curve cryptography enables various advanced cryptographic protocols. While some are in proof-of-concept stage without formal standards, they demonstrate the versatility of elliptic curve cryptography.

### Available Extensions

#### 1. Public Key Recovery from Signature

ECDSA signatures (including SM2) consist of two integers: **r** and **s**. Ethereum introduced an additional variable **v** (recovery identifier), making signatures {r, s, v}. Since SM2 signatures only use the X-coordinate of the random point (modulo N), multiple public keys can be recovered from a signature.

```go
// RecoverPublicKeysFromSM2Signature recovers two or four SM2 public keys 
// from a given signature and hash.
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error)
```

**Recovered Public Keys:**
- **Public Key 0**: Rx = (r - e) mod N; Ry is even (compressFlag = 2)
- **Public Key 1**: Rx = (r - e) mod N; Ry is odd (compressFlag = 3)
- **Public Key 2**: Rx = ((r - e) mod N) + N; Ry is even (compressFlag = 2) *(rare)*
- **Public Key 3**: Rx = ((r - e) mod N) + N; Ry is odd (compressFlag = 3) *(rare)*

> 📝 **Note:** Typically, only the first two public keys are returned. The latter two only exist when `(r - e) mod N < P - 1 - N`.

**Use Cases:**
- **Address Recovery**: Verify identity without transmitting public key
- **Compact Signatures**: Reduce signature size in space-constrained environments
- **Blockchain Applications**: Similar to Ethereum's signature recovery

---

#### 2. Partially Homomorphic Encryption (EC-ElGamal)

EC-ElGamal with SM2 curve provides **partially homomorphic encryption**, supporting addition operations on encrypted data.

**Supported Types:**
- `uint32` - Unsigned 32-bit integers
- `int32` - Signed 32-bit integers

**Properties:**
- ✅ **Additive Homomorphism**: `E(a) + E(b) = E(a + b)`
- ✅ **Scalar Multiplication**: `k * E(a) = E(k * a)`
- ❌ **Limited Range**: Practical for small values due to discrete log computation

**Implementation:** [github.com/emmansun/sm2elgamal](https://github.com/emmansun/sm2elgamal)

**Example Use Case:**
```go
// Electronic voting: Add encrypted votes without decryption
encryptedVote1 := Encrypt(publicKey, 1)  // Vote "yes"
encryptedVote2 := Encrypt(publicKey, 0)  // Vote "no"
encryptedTotal := Add(encryptedVote1, encryptedVote2)
totalVotes := Decrypt(privateKey, encryptedTotal) // Result: 1
```

---

#### 3. Ring Signatures

Ring signatures provide **signer anonymity** within a group. Anyone in the ring could have produced the signature, but the actual signer remains anonymous.

**Properties:**
- ✅ **Unconditional Anonymity**: Even computationally unbounded adversaries cannot determine the signer
- ✅ **No Group Manager**: No trusted third party required
- ✅ **Spontaneous Groups**: Ring can be formed ad-hoc without member cooperation

**Implementation:** [github.com/emmansun/sm2rsign](https://github.com/emmansun/sm2rsign)

**Use Cases:**
- **Whistleblowing**: Anonymous but authenticated disclosures
- **Confidential Transactions**: Privacy-preserving blockchain transactions
- **Anonymous Authentication**: Prove membership without revealing identity

---

### Other Potential Extensions

While not yet implemented, SM2 can theoretically support:

#### Deterministic Signatures
- **Standard**: [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979)
- **Benefit**: Removes dependency on secure random number generation
- **Use Case**: Embedded systems with poor entropy sources

#### Verifiable Random Functions (VRF)
- **Standard**: [IETF CFRG VRF](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-04)
- **Property**: Pseudorandom output with publicly verifiable proof
- **Use Case**: Blockchain consensus, lottery systems

#### Blind Signatures
- **Property**: Signer signs without seeing message content
- **Use Case**: Digital cash, privacy-preserving credentials

#### Threshold Signatures
- **Property**: Requires cooperation of multiple parties to create signature
- **Use Case**: Multi-party authorization, distributed key management

#### Pedersen Commitments
- **Reference**: [Cryptography Stack Exchange](https://crypto.stackexchange.com/questions/64437/what-is-a-pedersen-commitment)
- **Property**: Commit to value without revealing it, with binding and hiding properties
- **Use Case**: Zero-knowledge proofs, confidential transactions

---

### Implementation Status

| **Extension** | **Status** | **Repository** |
|--------------|-----------|----------------|
| Public Key Recovery | ✅ Implemented | Core GMSM library |
| EC-ElGamal PHE | ✅ POC Available | [sm2elgamal](https://github.com/emmansun/sm2elgamal) |
| Ring Signatures | ✅ POC Available | [sm2rsign](https://github.com/emmansun/sm2rsign) |
| Deterministic Signatures | ⏳ Planned | - |
| ECVRF | ⏳ Planned | - |
| Blind Signatures | ⏳ Research | - |
| Threshold Signatures | ⏳ Research | - |
| Pedersen Commitments | ⏳ Research | - |

> ⚠️ **Note:** Extensions marked as POC (Proof of Concept) are experimental and lack formal standards. They should not be used in production without thorough security review.

---

## API Reference

For complete API documentation, visit: [GMSM API Documentation](https://godoc.org/github.com/emmansun/gmsm)

### Quick Links

- **SM2 Package**: [godoc.org/github.com/emmansun/gmsm/sm2](https://godoc.org/github.com/emmansun/gmsm/sm2)
- **ECDH Package**: [godoc.org/github.com/emmansun/gmsm/ecdh](https://godoc.org/github.com/emmansun/gmsm/ecdh)
- **SMX509 Package**: [godoc.org/github.com/emmansun/gmsm/smx509](https://godoc.org/github.com/emmansun/gmsm/smx509)
- **PKCS8 Package**: [godoc.org/github.com/emmansun/gmsm/pkcs8](https://godoc.org/github.com/emmansun/gmsm/pkcs8)

---

## Additional Resources

### Performance Analysis
- [SM2 Performance Optimization](https://github.com/emmansun/gmsm/wiki/SM2%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)
- [SM2 Encryption/Decryption Performance](https://github.com/emmansun/gmsm/wiki/SM2%E5%8A%A0%E8%A7%A3%E5%AF%86%E6%80%A7%E8%83%BD)
- [Constant-Time Implementation](https://github.com/emmansun/gmsm/wiki/is-my-code-constant-time%3F)

### Related Projects
- [TLCP Implementation](https://github.com/Trisia/gotlcp) - GB/T 38636-2020 Transport Layer Cryptography Protocol
- [PKCS#12 with SM Support](https://github.com/emmansun/go-pkcs12) - SM-enabled PKCS#12 library
- [mkcert for SM2](https://github.com/emmansun/mksmcert) - Development certificate generation tool

### Standards Documents
- [National Standards Full-Text System](https://openstd.samr.gov.cn/)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [RFC 8018: PKCS #5](https://datatracker.ietf.org/doc/html/rfc8018)

---

## Frequently Asked Questions

### Q: Should I use SM2 or RSA for new applications?

**A:** For new Chinese domestic applications, SM2 is recommended due to:
- ✅ Compliance with Chinese cryptographic regulations
- ✅ Smaller key sizes (256-bit SM2 ≈ 3072-bit RSA security)
- ✅ Better performance for signing and key exchange
- ✅ Native support in Chinese certificate authorities

For international applications, consider NIST P-256 or Ed25519 for broader compatibility.

---

### Q: Can I use SM2 keys with ECDSA?

**A:** **No.** SM2 and ECDSA, while both elliptic curve algorithms, are **not compatible**:
- Different signature algorithms (SM2 incorporates Z value)
- Different curves (SM2 uses sm2p256v1, not secp256r1)
- Different hash algorithms (SM3 vs SHA-256)

Attempting to use SM2 keys with ECDSA will result in invalid signatures.

---

### Q: How do I handle the Z value in SM2 signatures?

**A:** The Z value is automatically handled by the library:
- **Default UID**: `"1234567812345678"` (16 bytes)
- **Custom UID**: Use `sm2.NewSM2SignerOption(true, customUID)`
- **No Z value**: Pass `nil` as `SignerOpts` for hash-only signing

For KMS integration, use `sm2.CalculateSM2Hash()` to compute the hash with Z value.

---

### Q: What's the difference between C1C2C3 and C1C3C2?

**A:** These are different concatenation orders for SM2 ciphertext:
- **C1C2C3**: Legacy format (2010 standard)
- **C1C3C2**: Current format (2012+ standard)

The library automatically detects the format during decryption. For new implementations, use C1C3C2 or ASN.1 format.

---

### Q: How do I encrypt large files with SM2?

**A:** **Don't encrypt large files directly with SM2.** Use envelope encryption:

1. Generate a random symmetric key (e.g., SM4 256-bit)
2. Encrypt the file with SM4
3. Encrypt the SM4 key with SM2 public key
4. Store both encrypted file and encrypted key

This approach is faster, more secure, and follows industry best practices.

---

## License

This documentation is part of the GMSM project, licensed under the MIT License. See the main [LICENSE](../LICENSE) file for details.
