# Post-Quantum Cryptography (PQC)

## Overview

Post-Quantum Cryptography (PQC) refers to cryptographic algorithms designed to resist attacks from quantum computers. Large-scale quantum computers can exploit Shor's algorithm to break RSA, ECC (including SM2) and other classical public-key cryptosystems in polynomial time. The "Harvest Now, Decrypt Later" (HNDL) attack strategy poses an immediate threat to long-lived sensitive data.

NIST published a suite of post-quantum cryptography federal standards in 2024:

- **FIPS 203** (ML-KEM): A key encapsulation mechanism based on the Module Learning With Errors (Module-LWE) problem, formerly known as Kyber.
- **FIPS 204** (ML-DSA): A digital signature algorithm based on Module-LWE/SIS, formerly known as Dilithium.
- **FIPS 205** (SLH-DSA): A stateless hash-based digital signature algorithm, formerly known as SPHINCS+.

GMSM implements all three standards and provides integration support for X.509 certificates, CMS (PKCS#7), and TLS 1.3.

---

## ML-KEM (FIPS 203)

ML-KEM is a Key Encapsulation Mechanism (KEM) used to securely establish a shared key between two parties. It provides three parameter sets targeting different security levels:

| Parameter Set | Security Level      | Encap Key Size | Decap Key Size | Ciphertext Size | Shared Key Size |
|--------------|---------------------|----------------|----------------|-----------------|-----------------|
| ML-KEM-512   | 1 (≈ AES-128)       | 800 bytes      | 1632 bytes     | 768 bytes       | 32 bytes        |
| ML-KEM-768   | 3 (≈ AES-192)       | 1184 bytes     | 2400 bytes     | 1088 bytes      | 32 bytes        |
| ML-KEM-1024  | 5 (≈ AES-256)       | 1568 bytes     | 3168 bytes     | 1568 bytes      | 32 bytes        |

Go package: `github.com/emmansun/gmsm/mlkem`

### Key Generation

```go
import "github.com/emmansun/gmsm/mlkem"

// Generate a decapsulation key randomly
dk, err := mlkem.GenerateKey768(rand.Reader)

// Or derive deterministically from a 64-byte seed (d‖z)
seed := make([]byte, mlkem.SeedSize) // SeedSize = 64
rand.Read(seed)
dk, err = mlkem.NewDecapsulationKeyFromSeed768(seed)
```

### Encapsulation (Sender)

```go
// Obtain the encapsulation key from the decapsulation key
ek := dk.EncapsulationKey()

// Encapsulate: produce a shared key and ciphertext
sharedKey, ciphertext, err := ek.Encapsulate(rand.Reader)
// sharedKey: 32 bytes, suitable for symmetric encryption
// ciphertext: transmitted to the decapsulating party
```

### Decapsulation (Receiver)

```go
// Recover the shared key from the ciphertext
sharedKey, err := dk.Decapsulate(ciphertext)
// sharedKey is identical to the sender's sharedKey
```

### Serialization

```go
// Decapsulation key
seed := dk.Seed()      // 64 bytes — recommended storage format
expanded := dk.Bytes() // Full expanded format

// Encapsulation key (for distribution to the peer)
ekBytes := dk.EncapsulationKey().Bytes()

// Restore an encapsulation key from bytes
ek, err = mlkem.NewEncapsulationKey768(ekBytes)
```

> **Note**: For ML-KEM-512 and ML-KEM-1024, replace `768` in function names with `512` or `1024`. The API is symmetric.

---

## ML-DSA (FIPS 204)

ML-DSA is a digital signature algorithm available in three security-level parameter sets:

| Parameter Set | Security Level      | Public Key | Private Key | Signature |
|--------------|---------------------|------------|-------------|-----------|
| ML-DSA-44    | 2 (≈ AES-128)       | 1312 bytes | 2560 bytes  | 2420 bytes|
| ML-DSA-65    | 3 (≈ AES-192)       | 1952 bytes | 4032 bytes  | 3309 bytes|
| ML-DSA-87    | 5 (≈ AES-256)       | 2592 bytes | 4896 bytes  | 4627 bytes|

Go package: `github.com/emmansun/gmsm/mldsa`

### Key Types

Each parameter set exposes two key type families:

- **`Key44`** (`Key65`, `Key87`): A combined key that holds the seed and implements `crypto.Signer`. Recommended for most use cases.
- **`PrivateKey44`** (`PrivateKey65`, `PrivateKey87`): An expanded private key with faster signing (no per-operation seed expansion).

### Key Generation

```go
import "github.com/emmansun/gmsm/mldsa"

// Generate randomly (returns Key44, implements crypto.Signer)
key, err := mldsa.GenerateKey44(rand.Reader)

// Derive deterministically from a 32-byte seed
seed := make([]byte, mldsa.SeedSize) // SeedSize = 32
rand.Read(seed)
key, err = mldsa.NewKey44(seed)

// Get expanded private key for faster repeated signing
priv := key.PrivateKey()
```

### Signing

ML-DSA supports two signing modes:

**Pure signing (recommended)**: Sign the message directly, without pre-hashing.

```go
opts := &mldsa.Options{} // default: pure signing, no context
sig, err := key.SignMessage(rand.Reader, message, opts)

// Signing with a context string (up to 255 bytes)
opts = &mldsa.Options{Context: []byte("my-protocol-context")}
sig, err = key.SignMessage(rand.Reader, message, opts)
```

**Pre-hash mode (HashML-DSA)**: Compatible with the `crypto.Signer` interface; hashes the message before signing.

```go
// Set the pre-hash algorithm OID
opts = &mldsa.Options{
    PrehashOID: mldsa.OIDDigestAlgorithmSHA256,
}
// Pass the original message; hashing is done internally
sig, err = key.SignMessage(rand.Reader, message, opts)

// Supported pre-hash algorithms:
// mldsa.OIDDigestAlgorithmSHA256
// mldsa.OIDDigestAlgorithmSHA512
// mldsa.OIDDigestAlgorithmSHA3_256 / SHA3_384 / SHA3_512
// mldsa.OIDDigestAlgorithmSHAKE128 / SHAKE256
// mldsa.OIDDigestAlgorithmSM3
```

### Verification

```go
pk := key.Public().(*mldsa.PublicKey44)

// Use the same opts as during signing
ok := pk.VerifyWithOptions(sig, message, opts)

// Restore a public key from bytes
pk, err = mldsa.NewPublicKey44(pkBytes)
```

### Serialization

```go
// Key44 (with seed)
seedBytes := key.Seed()               // 32 bytes — recommended storage
pk := key.Public().(*mldsa.PublicKey44)
pkBytes := pk.Bytes()                 // 1312 bytes

// Restore
key, err = mldsa.NewKey44(seedBytes)
pk, err  = mldsa.NewPublicKey44(pkBytes)

// PrivateKey44 (expanded format)
privBytes := priv.Bytes()             // 2560 bytes
priv, err  = mldsa.NewPrivateKey44(privBytes)
```

### crypto.Signer Compatibility

`Key44`, `Key65`, and `Key87` all implement `crypto.Signer`, making them directly usable with the standard library's TLS and X.509 certificate APIs:

```go
var signer crypto.Signer = key // Key44 implements crypto.Signer
```

### X.509 Certificate Integration (RFC 9881)

The `smx509` package supports ML-DSA in X.509 certificates. RFC 9881 defines the X.509 algorithm identifiers for ML-DSA.

| Algorithm  | SignatureAlgorithm Constant   | OID                           |
|-----------|-------------------------------|-------------------------------|
| ML-DSA-44 | `smx509.MLDSA44` (100)        | 2.16.840.1.101.3.4.3.17       |
| ML-DSA-65 | `smx509.MLDSA65` (101)        | 2.16.840.1.101.3.4.3.18       |
| ML-DSA-87 | `smx509.MLDSA87` (102)        | 2.16.840.1.101.3.4.3.19       |

```go
import "github.com/emmansun/gmsm/smx509"

// Issue an ML-DSA-65 self-signed certificate
template := &smx509.Certificate{
    SerialNumber:       big.NewInt(1),
    Subject:            pkix.Name{CommonName: "ML-DSA Test"},
    NotBefore:          time.Now(),
    NotAfter:           time.Now().Add(365 * 24 * time.Hour),
    SignatureAlgorithm: smx509.MLDSA65,
    PublicKeyAlgorithm: smx509.PKMLDSA65,
}
key65, _ := mldsa.GenerateKey65(rand.Reader)
certDER, err := smx509.CreateCertificate(rand.Reader, template, template, key65.Public(), key65)
```

> **Note**: ML-DSA is a "pure" signature scheme. X.509 integration does **not** use pre-hashing (`crypto.Hash(0)`).

### CMS (PKCS#7) Integration (RFC 9882)

RFC 9882 defines the use of ML-DSA in CMS (Cryptographic Message Syntax), using the same OIDs as RFC 9881.

```go
import "github.com/emmansun/gmsm/pkcs7"

// Sign using an ML-DSA key
p7, err := pkcs7.NewSignedData(content)
err = p7.AddSigner(cert, key65, pkcs7.SignerInfoConfig{})
signedData, err := p7.Finish()

// Verify
p7, err = pkcs7.Parse(signedData)
err = p7.Verify()
```

---

## SLH-DSA (FIPS 205)

SLH-DSA is a stateless hash-based digital signature scheme. Its security relies solely on the properties of the underlying hash function, providing the most conservative resistance against quantum attacks.

### Parameter Sets

SLH-DSA provides 12 standardized parameter sets (SHA2 and SHAKE families), plus 2 SM3-based extensions provided by this project:

| Parameter Set Name       | Go Variable               | Security Level | Speed | PK (B) | SK (B) | Sig (B) |
|--------------------------|---------------------------|----------------|-------|--------|--------|---------|
| SLH-DSA-SHA2-128s        | `SLHDSA128SmallSHA2`      | 1              | Slow  | 32     | 64     | 7856    |
| SLH-DSA-SHA2-128f        | `SLHDSA128FastSHA2`       | 1              | Fast  | 32     | 64     | 17088   |
| SLH-DSA-SHA2-192s        | `SLHDSA192SmallSHA2`      | 3              | Slow  | 48     | 96     | 16224   |
| SLH-DSA-SHA2-192f        | `SLHDSA192FastSHA2`       | 3              | Fast  | 48     | 96     | 35664   |
| SLH-DSA-SHA2-256s        | `SLHDSA256SmallSHA2`      | 5              | Slow  | 64     | 128    | 29792   |
| SLH-DSA-SHA2-256f        | `SLHDSA256FastSHA2`       | 5              | Fast  | 64     | 128    | 49856   |
| SLH-DSA-SHAKE-128s       | `SLHDSA128SmallSHAKE`     | 1              | Slow  | 32     | 64     | 7856    |
| SLH-DSA-SHAKE-128f       | `SLHDSA128FastSHAKE`      | 1              | Fast  | 32     | 64     | 17088   |
| SLH-DSA-SHAKE-192s       | `SLHDSA192SmallSHAKE`     | 3              | Slow  | 48     | 96     | 16224   |
| SLH-DSA-SHAKE-192f       | `SLHDSA192FastSHAKE`      | 3              | Fast  | 48     | 96     | 35664   |
| SLH-DSA-SHAKE-256s       | `SLHDSA256SmallSHAKE`     | 5              | Slow  | 64     | 128    | 29792   |
| SLH-DSA-SHAKE-256f       | `SLHDSA256FastSHAKE`      | 5              | Fast  | 64     | 128    | 49856   |
| SLH-DSA-SM3-128s ¹       | `SLHDSA128SmallSM3`       | 1              | Slow  | 32     | 64     | 7856    |
| SLH-DSA-SM3-128f ¹       | `SLHDSA128FastSM3`        | 1              | Fast  | 32     | 64     | 17088   |

¹ SM3 parameter sets are GMSM extensions with no standardized OID; X.509/CMS integration is not supported.

**Small (s) vs. Fast (f)**: Small parameter sets produce smaller signatures at the cost of slower signing/verification; Fast parameter sets are faster but produce larger signatures.

Go package: `github.com/emmansun/gmsm/slhdsa`

### Accessing Parameter Sets

```go
import "github.com/emmansun/gmsm/slhdsa"

// Reference a parameter set directly via the package-level variable
params := &slhdsa.SLHDSA128SmallSHA2

// Look up by canonical name
params, ok := slhdsa.GetParameterSet("SLH-DSA-SHA2-128s")

// Look up by OID
params, ok = slhdsa.GetParameterSetByOID(oid)
```

### Key Generation

```go
// Generate randomly
sk, err := params.GenerateKey(rand.Reader)

// Obtain the public key
pk := sk.Public().(*slhdsa.PublicKey)
// or equivalently
pk = sk.PublicKey()
```

### Signing

SLH-DSA also supports pure signing and pre-hash modes:

```go
// Pure signing (recommended)
opts := &slhdsa.Options{}
sig, err := sk.SignMessage(rand.Reader, message, opts)

// With a context string
opts = &slhdsa.Options{Context: []byte("my-context")}
sig, err = sk.SignMessage(rand.Reader, message, opts)

// Pre-hash mode (HashSLH-DSA)
opts = &slhdsa.Options{
    PrehashOID: slhdsa.OIDDigestAlgorithmSHA256,
}
sig, err = sk.SignMessage(rand.Reader, message, opts)
```

### Verification

```go
ok := pk.VerifyWithOptions(sig, message, opts)
// opts must match those used during signing
```

### Serialization

```go
// Private key
skBytes := sk.Bytes()
sk, err = params.NewPrivateKey(skBytes)

// Public key
pkBytes := pk.Bytes()
pk, err = params.NewPublicKey(pkBytes)

// Parameter set metadata
paramSet := pk.ParameterSet()   // *slhdsa.ParameterSet
oid := pk.OID()                 // asn1.ObjectIdentifier (nil for SM3 sets)
```

### X.509 Certificate Integration (RFC 9909)

RFC 9909 defines X.509 algorithm identifiers for the 12 standard SLH-DSA parameter sets.

| Parameter Set            | SignatureAlgorithm Constant       | OID                           |
|--------------------------|----------------------------------|-------------------------------|
| SLH-DSA-SHA2-128s        | `smx509.SLHDSASHA2128s` (110)    | 2.16.840.1.101.3.4.3.20       |
| SLH-DSA-SHA2-128f        | `smx509.SLHDSASHA2128f` (111)    | 2.16.840.1.101.3.4.3.21       |
| SLH-DSA-SHA2-192s        | `smx509.SLHDSASHA2192s` (112)    | 2.16.840.1.101.3.4.3.22       |
| SLH-DSA-SHA2-192f        | `smx509.SLHDSASHA2192f` (113)    | 2.16.840.1.101.3.4.3.23       |
| SLH-DSA-SHA2-256s        | `smx509.SLHDSASHA2256s` (114)    | 2.16.840.1.101.3.4.3.24       |
| SLH-DSA-SHA2-256f        | `smx509.SLHDSASHA2256f` (115)    | 2.16.840.1.101.3.4.3.25       |
| SLH-DSA-SHAKE-128s       | `smx509.SLHDSASHAKE128s` (116)   | 2.16.840.1.101.3.4.3.26       |
| SLH-DSA-SHAKE-128f       | `smx509.SLHDSASHAKE128f` (117)   | 2.16.840.1.101.3.4.3.27       |
| SLH-DSA-SHAKE-192s       | `smx509.SLHDSASHAKE192s` (118)   | 2.16.840.1.101.3.4.3.28       |
| SLH-DSA-SHAKE-192f       | `smx509.SLHDSASHAKE192f` (119)   | 2.16.840.1.101.3.4.3.29       |
| SLH-DSA-SHAKE-256s       | `smx509.SLHDSASHAKE256s` (120)   | 2.16.840.1.101.3.4.3.30       |
| SLH-DSA-SHAKE-256f       | `smx509.SLHDSASHAKE256f` (121)   | 2.16.840.1.101.3.4.3.31       |

```go
template := &smx509.Certificate{
    SignatureAlgorithm: smx509.SLHDSASHA2128s,
    PublicKeyAlgorithm: smx509.PKSLHDSASHA2128s,
    // ...
}
sk, _ := slhdsa.SLHDSA128SmallSHA2.GenerateKey(rand.Reader)
certDER, err := smx509.CreateCertificate(rand.Reader, template, template, sk.Public(), sk)
```

### CMS (PKCS#7) Integration (RFC 9814)

RFC 9814 defines the use of SLH-DSA in CMS, using the same OIDs as RFC 9909.

```go
p7, err := pkcs7.NewSignedData(content)
err = p7.AddSigner(cert, sk, pkcs7.SignerInfoConfig{})
signedData, err := p7.Finish()
```

---

## TLS 1.3 Hybrid Key Exchange

During the transition to the post-quantum era, "hybrid key exchange" is recommended: run classical ECDH and ML-KEM simultaneously so that an attacker must break both to compromise the session.

GMSM's `tls13` package implements the key exchange primitives defined in [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/).

Go package: `github.com/emmansun/gmsm/tls13`

### Supported Named Groups

| Named Group         | `CurveID` Constant     | Value  | Composition                    |
|--------------------|------------------------|--------|-------------------------------|
| x25519             | `CurveX25519`          | 0x001D | Pure X25519                   |
| secp256r1          | `CurveP256`            | 0x0017 | Pure P-256                    |
| secp384r1          | `CurveP384`            | 0x0018 | Pure P-384                    |
| secp521r1          | `CurveP521`            | 0x0019 | Pure P-521                    |
| curveSM2           | `CurveSM2`             | 0x0029 | Pure SM2 (RFC 8998)           |
| X25519MLKEM768     | `X25519MLKEM768`       | 0x11ec | X25519 + ML-KEM-768           |
| SecP256r1MLKEM768  | `SecP256r1MLKEM768`    | 0x11eb | P-256 + ML-KEM-768            |
| SecP384r1MLKEM1024 | `SecP384r1MLKEM1024`   | 0x11ed | P-384 + ML-KEM-1024           |
| SM2MLKEM768 ²      | `SM2MLKEM768`          | 0x11ee | SM2 + ML-KEM-768 (extension)  |

² `SM2MLKEM768` is a GMSM extension, not yet part of any IETF standard.

### Key Share Data Format

The key share payload for hybrid groups is the concatenation of the classical and ML-KEM key shares. The ordering is group-specific:

| Named Group         | ClientHello data                                          | ServerHello data                                         |
|--------------------|-----------------------------------------------------------|----------------------------------------------------------|
| X25519MLKEM768     | ML-KEM-768 encap key (1184 B) ‖ X25519 (32 B)            | ML-KEM-768 ciphertext (1088 B) ‖ X25519 (32 B)          |
| SecP256r1MLKEM768  | P-256 point (65 B) ‖ ML-KEM-768 encap key (1184 B)       | P-256 point (65 B) ‖ ML-KEM-768 ciphertext (1088 B)     |
| SecP384r1MLKEM1024 | P-384 point (97 B) ‖ ML-KEM-1024 encap key (1568 B)      | P-384 point (97 B) ‖ ML-KEM-1024 ciphertext (1568 B)    |
| SM2MLKEM768        | SM2 point (65 B) ‖ ML-KEM-768 encap key (1184 B)         | SM2 point (65 B) ‖ ML-KEM-768 ciphertext (1088 B)       |

The combined shared secret is the concatenation of the ECDH and ML-KEM shared secrets in the same order as the key share data.

### Client Flow

```go
import "github.com/emmansun/gmsm/tls13"

// Create a key exchange object
ke, err := tls13.NewKeyExchange(tls13.X25519MLKEM768)

// Generate ClientHello key shares
// clientKeyShares[0]: hybrid key share
// clientKeyShares[1]: classical-only fallback share
priv, clientKeyShares, err := ke.KeyShares(rand.Reader)

// Send clientKeyShares[0].Data to the server (in ClientHello)
// Receive serverKeyShare from the server (in ServerHello)

// Compute the shared secret from the server's key share
sharedSecret, err := ke.ClientSharedSecret(priv, serverKeyShare.Data)
```

### Server Flow

```go
ke, err := tls13.NewKeyExchange(tls13.X25519MLKEM768)

// Compute the shared secret and the server's key share from the client's share
sharedSecret, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShare)
// Put serverKeyShare.Data in ServerHello
```

### Pure ECDH Flow

```go
ke, err := tls13.NewKeyExchange(tls13.CurveP256)

// Client
priv, clientKeyShares, err := ke.KeyShares(rand.Reader)
// clientKeyShares[0].Data is the P-256 public key

// Server
sharedSecret, serverKeyShare, err := ke.ServerSharedSecret(rand.Reader, clientKeyShares[0].Data)

// Client completes
sharedSecret, err = ke.ClientSharedSecret(priv, serverKeyShare.Data)
```

---

## Reference Standards

| Standard                            | Description                                                              |
|-------------------------------------|--------------------------------------------------------------------------|
| NIST FIPS 203                       | ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)                |
| NIST FIPS 204                       | ML-DSA (Module-Lattice-Based Digital Signature Algorithm)                |
| NIST FIPS 205                       | SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)               |
| RFC 9881                            | Use of ML-DSA in X.509 Public Key Certificates and CRLs                 |
| RFC 9882                            | Use of ML-DSA in CMS                                                    |
| RFC 9909                            | Use of SLH-DSA in X.509 Public Key Certificates and CRLs                |
| RFC 9814                            | Use of SLH-DSA in CMS                                                   |
| RFC 8998                            | ShangMi (SM) Cipher Suites for TLS 1.3                                  |
| draft-ietf-tls-hybrid-design        | Hybrid Key Exchange in TLS 1.3                                           |
