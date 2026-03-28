# PQC Standards Implementation Manual

A comprehensive developer guide for integrating post-quantum cryptography into your applications using this multi-language library.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start](#2-quick-start)
3. [ML-KEM (FIPS 203) -- Key Encapsulation](#3-ml-kem-fips-203--key-encapsulation)
4. [ML-DSA (FIPS 204) -- Digital Signatures](#4-ml-dsa-fips-204--digital-signatures)
5. [SLH-DSA (FIPS 205) -- Hash-Based Signatures](#5-slh-dsa-fips-205--hash-based-signatures)
6. [Hybrid KEMs](#6-hybrid-kems)
7. [Composite Signatures](#7-composite-signatures)
8. [TLS 1.3 Integration](#8-tls-13-integration)
9. [Parameter Set Selection Guide](#9-parameter-set-selection-guide)
10. [Security Considerations](#10-security-considerations)
11. [Migration Guide](#11-migration-guide)
12. [Building and Testing](#12-building-and-testing)
    - [Cross-Language Interoperability Suite](#cross-language-interoperability-suite)
13. [Performance](#13-performance)
14. [FAQ](#14-faq)
15. [License](#15-license)

---

## 1. Introduction

### What is Post-Quantum Cryptography

Post-quantum cryptography (PQC) refers to cryptographic algorithms that remain secure against attacks by both classical and quantum computers. Current widely deployed algorithms such as RSA, ECDH, and ECDSA rely on the difficulty of integer factoring or discrete logarithm problems, which quantum computers running Shor's algorithm can solve efficiently.

PQC algorithms are built on mathematical problems believed to resist quantum attacks, including lattice problems (ML-KEM, ML-DSA) and hash-based constructions (SLH-DSA).

### Why You Need It Now

The primary urgency comes from the "harvest now, decrypt later" threat model. Adversaries can record encrypted communications today and store them until sufficiently powerful quantum computers become available. This means data encrypted with classical algorithms that needs to remain confidential for years or decades is already at risk.

Organizations handling long-lived secrets -- government communications, healthcare records, financial data, intellectual property -- should begin transitioning to post-quantum algorithms now.

### NIST Standards Overview

In August 2024, NIST published three post-quantum cryptographic standards:

- **FIPS 203 (ML-KEM)** -- Module-Lattice-Based Key-Encapsulation Mechanism. Derived from CRYSTALS-Kyber. Used for key exchange and key transport.
- **FIPS 204 (ML-DSA)** -- Module-Lattice-Based Digital Signature Algorithm. Derived from CRYSTALS-Dilithium. Used for digital signatures.
- **FIPS 205 (SLH-DSA)** -- Stateless Hash-Based Digital Signature Algorithm. Derived from SPHINCS+. A conservative backup signature scheme based solely on hash function security.

### What This Library Provides

This repository contains pure implementations of all three NIST PQC standards across eight programming languages. Cross-language interoperability is verified by a shared test vector suite — **96/96 tests pass** across Python, Go, Java, JavaScript, Rust, Swift, .NET, and PHP.

| Component | Rust | Go | JS | Python | Java | C# | Swift | PHP |
|-----------|------|----|----|--------|------|----|-------|-----|
| ML-KEM (FIPS 203) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA (FIPS 204) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SLH-DSA SHAKE (FIPS 205) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SLH-DSA SHA2 (FIPS 205) | — | ✅ | — | — | — | — | — | — |
| Hybrid KEM | — | ✅ | — | — | — | — | — | — |
| Composite Signatures | — | ✅ | — | — | — | — | — | — |
| PQ-TLS 1.3 | — | ✅ | — | — | — | — | — | — |

**Test vectors** are stored in `test-vectors/` organized by algorithm family:

```
test-vectors/
├── ml-kem/          ML-KEM-512, ML-KEM-768, ML-KEM-1024
├── ml-dsa/          ML-DSA-44, ML-DSA-65, ML-DSA-87
├── slh-dsa/
│   ├── shake/       SLH-DSA-SHAKE-{128,192,256}{f,s}
│   └── sha2/        SLH-DSA-SHA2-{128,192,256}{f,s}
├── hybrid-kem/      X25519+ML-KEM-768/1024, ECDH-P256/P384+ML-KEM
├── composite-sig/   ML-DSA-{44,65,87}+Ed25519, ML-DSA-65+ECDSA-P256
└── pq-tls/          PQ-TLS 1.3 X25519MLKEM768 key exchange
```

Generate fresh vectors (from repo root):
```bash
cd go && go run ./cmd/generate-all-vectors ../test-vectors
```

Run the full cross-language interop suite:
```bash
bash interop/run_interop_comprehensive.sh
```

---

## 2. Quick Start

### Rust

```rust
// ML-KEM key exchange
use ml_kem::{keygen, encapsulate, decapsulate, MlKem768};
use rand::rngs::OsRng;

let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
let (shared_secret, ciphertext) = encapsulate::<MlKem768>(&ek, &mut OsRng);
let recovered = decapsulate::<MlKem768>(&dk, &ciphertext);
assert_eq!(shared_secret, recovered);
```

```rust
// ML-DSA signing
use ml_dsa::dsa::{keygen, sign, verify};
use ml_dsa::params::MlDsa65;
use rand::rngs::OsRng;

let (pk, sk) = keygen::<MlDsa65>(&mut OsRng);
let sig = sign::<MlDsa65>(&sk, b"hello world", &mut OsRng);
assert!(verify::<MlDsa65>(&pk, b"hello world", &sig));
```

### Go

```go
// ML-KEM key exchange
import (
    "crypto/rand"
    "github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
    "github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
)

ek, dk, _ := mlkem.KeyGen(params.MlKem768, rand.Reader)
ss, ct, _ := mlkem.Encapsulate(params.MlKem768, ek, rand.Reader)
recovered := mlkem.Decapsulate(params.MlKem768, dk, ct)
// ss == recovered
```

```go
// ML-DSA signing
import "github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"

pk, sk := mldsa.KeyGen(mldsa.MLDSA65)
sig := mldsa.Sign(sk, []byte("hello world"), mldsa.MLDSA65)
valid := mldsa.Verify(pk, []byte("hello world"), sig, mldsa.MLDSA65)
```

### JavaScript (Node.js)

```js
// ML-KEM key exchange
import { keyGen, encaps, decaps, ML_KEM_768 } from '@pqc/ml-kem';

const { ek, dk } = keyGen(ML_KEM_768);
const { K, c } = encaps(ek, ML_KEM_768);
const recovered = decaps(dk, c, ML_KEM_768);
// K and recovered are equal
```

```js
// ML-DSA signing
import { keyGen, sign, verify, ML_DSA_65 } from '@pqc/ml-dsa';

const { pk, sk } = keyGen(ML_DSA_65);
const sig = sign(sk, new TextEncoder().encode('hello world'), ML_DSA_65);
const valid = verify(pk, new TextEncoder().encode('hello world'), sig, ML_DSA_65);
```

### Python

```python
# ML-KEM key exchange
from mlkem import keygen, encaps, decaps, ML_KEM_768

ek, dk = keygen(ML_KEM_768)
shared_secret, ciphertext = encaps(ek, ML_KEM_768)
recovered = decaps(dk, ciphertext, ML_KEM_768)
assert shared_secret == recovered
```

```python
# ML-DSA signing
from mldsa import keygen, sign, verify, ML_DSA_65

pk, sk = keygen(ML_DSA_65)
sig = sign(sk, b"hello world", ML_DSA_65)
assert verify(pk, b"hello world", sig, ML_DSA_65)
```

### Java

```java
// ML-KEM key exchange
import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;

MLKEM.KeyPair kp = MLKEM.keyGen(Params.ML_KEM_768);
MLKEM.EncapsResult enc = MLKEM.encaps(kp.ek(), Params.ML_KEM_768);
byte[] recovered = MLKEM.decaps(kp.dk(), enc.ciphertext(), Params.ML_KEM_768);
```

```java
// ML-DSA signing
import com.pqc.mldsa.MLDSA;
import com.pqc.mldsa.DsaParams;

MLDSA.KeyPair kp = MLDSA.keyGen(DsaParams.ML_DSA_65);
byte[] sig = MLDSA.sign(kp.sk(), "hello world".getBytes(), DsaParams.ML_DSA_65);
boolean valid = MLDSA.verify(kp.pk(), "hello world".getBytes(), sig, DsaParams.ML_DSA_65);
```

### C# (.NET)

```csharp
// ML-KEM key exchange
using PqcStandards.MlKem;

var (ek, dk) = MlKemAlgorithm.KeyGen(MlKemParams.MlKem768);
var (K, ct) = MlKemAlgorithm.Encaps(MlKemParams.MlKem768, ek);
var recovered = MlKemAlgorithm.Decaps(MlKemParams.MlKem768, dk, ct);
```

```csharp
// ML-DSA signing
using PqcStandards.MlDsa;

var (pk, sk) = MlDsaAlgorithm.KeyGen(MlDsaParams.MlDsa65);
var sig = MlDsaAlgorithm.Sign(sk, "hello world"u8.ToArray(), MlDsaParams.MlDsa65);
bool valid = MlDsaAlgorithm.Verify(pk, "hello world"u8.ToArray(), sig, MlDsaParams.MlDsa65);
```

### Swift

```swift
// ML-KEM key exchange
import PQCStandards

let kp = MlKem.keyGen(params: .mlKem768)
let enc = MlKem.encapsulate(params: .mlKem768, ek: kp.encapsulationKey)
let recovered = MlKem.decapsulate(params: .mlKem768, dk: kp.decapsulationKey, ct: enc.ciphertext)
// enc.sharedSecret == recovered
```

```swift
// ML-DSA signing
let (pk, sk) = MlDsa.keyGen(params: .mlDsa65)
let sig = MlDsa.sign(sk: sk, message: Array("hello world".utf8), params: .mlDsa65)
let valid = MlDsa.verify(pk: pk, message: Array("hello world".utf8), sig: sig, params: .mlDsa65)
```

### PHP

```php
// ML-KEM key exchange
use PQC\MlKem\MlKem;

$keys = MlKem::keyGen(768);
$enc = MlKem::encaps($keys['ek'], 768);
$recovered = MlKem::decaps($keys['dk'], $enc['ct'], 768);
// $enc['ss'] === $recovered
```

```php
// ML-DSA signing
use PQC\MlDsa\MlDsa;

$kp = MlDsa::keyGen(65);
$sig = MlDsa::sign($kp['sk'], 'hello world', 65);
$valid = MlDsa::verify($kp['pk'], 'hello world', $sig, 65);
```

---

## 3. ML-KEM (FIPS 203) -- Key Encapsulation

### Overview

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) enables two parties to establish a shared secret over an insecure channel. It is the post-quantum replacement for ECDH and RSA key transport.

The mechanism works in three steps:

1. **KeyGen** -- The receiver generates an encapsulation key (public) and a decapsulation key (private).
2. **Encaps** -- The sender uses the encapsulation key to produce a shared secret and a ciphertext.
3. **Decaps** -- The receiver uses the decapsulation key and the ciphertext to recover the same shared secret.

ML-KEM provides IND-CCA2 security through the Fujisaki-Okamoto transform applied to the underlying K-PKE encryption scheme.

### Parameter Sets

| Parameter Set | NIST Level | Encaps Key | Decaps Key | Ciphertext | Shared Secret |
|--------------|------------|------------|------------|------------|---------------|
| ML-KEM-512   | 1 (128-bit) | 800 bytes | 1632 bytes | 768 bytes  | 32 bytes      |
| ML-KEM-768   | 3 (192-bit) | 1184 bytes| 2400 bytes | 1088 bytes | 32 bytes      |
| ML-KEM-1024  | 5 (256-bit) | 1568 bytes| 3168 bytes | 1568 bytes | 32 bytes      |

**Recommendation:** Use **ML-KEM-768** for most applications. It provides a strong security margin at NIST Level 3 with reasonable key and ciphertext sizes.

### API Reference

#### Rust

```rust
use ml_kem::kem::{keygen, encapsulate, decapsulate};
use ml_kem::params::{MlKem512, MlKem768, MlKem1024};

// Key generation: returns (encapsulation_key, decapsulation_key)
let (ek, dk) = keygen::<MlKem768>(&mut rng);

// Encapsulation: returns (shared_secret, ciphertext)
let (ss, ct) = encapsulate::<MlKem768>(&ek, &mut rng);

// Decapsulation: returns shared_secret
let ss = decapsulate::<MlKem768>(&dk, &ct);
```

Parameter sets are type-level: `MlKem512`, `MlKem768`, `MlKem1024`.

#### Go

```go
import (
    "github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
    "github.com/liviuepure/PQC-Standards-Implementation/go/internal/params"
)

// Parameter sets: params.MlKem512, params.MlKem768, params.MlKem1024
ek, dk, err := mlkem.KeyGen(params.MlKem768, rand.Reader)
ss, ct, err := mlkem.Encapsulate(params.MlKem768, ek, rand.Reader)
recovered := mlkem.Decapsulate(params.MlKem768, dk, ct)
```

#### JavaScript

```js
import { keyGen, encaps, decaps, ML_KEM_512, ML_KEM_768, ML_KEM_1024 } from '@pqc/ml-kem';

const { ek, dk } = keyGen(ML_KEM_768);        // returns { ek: Uint8Array, dk: Uint8Array }
const { K, c } = encaps(ek, ML_KEM_768);       // returns { K: Uint8Array, c: Uint8Array }
const recovered = decaps(dk, c, ML_KEM_768);    // returns Uint8Array (32 bytes)
```

#### Python

```python
from mlkem import keygen, encaps, decaps, ML_KEM_512, ML_KEM_768, ML_KEM_1024

ek, dk = keygen(ML_KEM_768)                # returns (bytes, bytes)
shared_secret, ciphertext = encaps(ek, ML_KEM_768)  # returns (bytes, bytes)
recovered = decaps(dk, ciphertext, ML_KEM_768)       # returns bytes
```

#### Java

```java
import com.pqc.mlkem.MLKEM;
import com.pqc.mlkem.Params;  // Params.ML_KEM_512, ML_KEM_768, ML_KEM_1024

MLKEM.KeyPair kp = MLKEM.keyGen(Params.ML_KEM_768);
MLKEM.EncapsResult enc = MLKEM.encaps(kp.ek(), Params.ML_KEM_768);
byte[] recovered = MLKEM.decaps(kp.dk(), enc.ciphertext(), Params.ML_KEM_768);
// enc.sharedSecret() and recovered are identical
```

#### C#

```csharp
using PqcStandards.MlKem;
// Parameters: MlKemParams.MlKem512, MlKem768, MlKem1024

var (ek, dk) = MlKemAlgorithm.KeyGen(MlKemParams.MlKem768);
var (K, ct) = MlKemAlgorithm.Encaps(MlKemParams.MlKem768, ek);
var recovered = MlKemAlgorithm.Decaps(MlKemParams.MlKem768, dk, ct);
```

#### Swift

```swift
import PQCStandards

let kp = MlKem.keyGen(params: .mlKem768)
let enc = MlKem.encapsulate(params: .mlKem768, ek: kp.encapsulationKey)
let recovered = MlKem.decapsulate(params: .mlKem768, dk: kp.decapsulationKey, ct: enc.ciphertext)
```

#### PHP

```php
use PQC\MlKem\MlKem;

$keys = MlKem::keyGen(768);                   // ['ek' => string, 'dk' => string]
$enc = MlKem::encaps($keys['ek'], 768);       // ['ct' => string, 'ss' => string]
$recovered = MlKem::decaps($keys['dk'], $enc['ct'], 768);
```

PHP uses integer parameter levels: `512`, `768`, or `1024`.

### Security Considerations

- **Implicit rejection**: On decapsulation failure (tampered ciphertext), ML-KEM returns a pseudorandom value derived from the secret key and ciphertext via `J(z || ct)` rather than an error. This prevents decryption oracle attacks.
- **Constant-time operations**: All secret-dependent comparisons and selections use constant-time routines (`subtle.ConstantTimeCompare` in Go, `timingSafeEqual` in JS, `hmac.compare_digest` in Python, the `subtle` crate in Rust).
- **Encapsulation key validation**: Before encapsulation, the library validates that all decoded coefficients are within bounds (less than q = 3329). Invalid keys cause an error rather than silent misbehavior.

### Choosing a Parameter Set

- **ML-KEM-768**: Recommended for most applications. NIST Level 3 security with good performance.
- **ML-KEM-512**: Use only when bandwidth is severely constrained and Level 1 security suffices.
- **ML-KEM-1024**: Use when maximum security is required (NIST Level 5) and larger keys are acceptable.

---

## 4. ML-DSA (FIPS 204) -- Digital Signatures

### Overview

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is the post-quantum replacement for ECDSA, EdDSA, and RSA signatures. It provides existential unforgeability under chosen message attack (EUF-CMA).

The algorithm uses a rejection sampling loop during signing: it generates candidate signatures and discards those that would leak information about the secret key. This means signing time has some variance.

### Parameter Sets

| Parameter Set | NIST Level | Public Key | Secret Key | Signature | Sign Iters (avg) |
|--------------|------------|------------|------------|-----------|-------------------|
| ML-DSA-44    | 2 (128-bit) | 1312 bytes| 2560 bytes | 2420 bytes | ~4.25             |
| ML-DSA-65    | 3 (192-bit) | 1952 bytes| 4032 bytes | 3309 bytes | ~5.1              |
| ML-DSA-87    | 5 (256-bit) | 2592 bytes| 4896 bytes | 4627 bytes | ~3.85             |

**Recommendation:** Use **ML-DSA-65** for most applications. It provides NIST Level 3 security with a good balance of key size and performance.

### API Reference

#### Rust

```rust
use ml_dsa::dsa::{keygen, sign, verify};
use ml_dsa::params::{MlDsa44, MlDsa65, MlDsa87};

let (pk, sk) = keygen::<MlDsa65>(&mut rng);
let sig = sign::<MlDsa65>(&sk, message, &mut rng);
let valid: bool = verify::<MlDsa65>(&pk, message, &sig);
```

#### Go

```go
import "github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"

// Parameters: mldsa.MLDSA44, mldsa.MLDSA65, mldsa.MLDSA87
pk, sk := mldsa.KeyGen(mldsa.MLDSA65)
sig := mldsa.Sign(sk, msg, mldsa.MLDSA65)
valid := mldsa.Verify(pk, msg, sig, mldsa.MLDSA65)
```

#### JavaScript

```js
import { keyGen, sign, verify, ML_DSA_44, ML_DSA_65, ML_DSA_87 } from '@pqc/ml-dsa';

const { pk, sk } = keyGen(ML_DSA_65);
const sig = sign(sk, message, ML_DSA_65);
const valid = verify(pk, message, sig, ML_DSA_65);
```

#### Python

```python
from mldsa import keygen, sign, verify, ML_DSA_44, ML_DSA_65, ML_DSA_87

pk, sk = keygen(ML_DSA_65)
sig = sign(sk, message, ML_DSA_65)
assert verify(pk, message, sig, ML_DSA_65)
```

#### Java

```java
import com.pqc.mldsa.MLDSA;
import com.pqc.mldsa.DsaParams;

// Parameters: DsaParams.ML_DSA_44, ML_DSA_65, ML_DSA_87
MLDSA.KeyPair kp = MLDSA.keyGen(DsaParams.ML_DSA_65);
byte[] sig = MLDSA.sign(kp.sk(), msg, DsaParams.ML_DSA_65);
boolean valid = MLDSA.verify(kp.pk(), msg, sig, DsaParams.ML_DSA_65);
```

#### C#

```csharp
using PqcStandards.MlDsa;

var (pk, sk) = MlDsaAlgorithm.KeyGen(MlDsaParams.MlDsa65);
var sig = MlDsaAlgorithm.Sign(sk, message, MlDsaParams.MlDsa65);
bool valid = MlDsaAlgorithm.Verify(pk, message, sig, MlDsaParams.MlDsa65);
```

#### Swift

```swift
import PQCStandards

let (pk, sk) = MlDsa.keyGen(params: .mlDsa65)
let sig = MlDsa.sign(sk: sk, message: messageBytes, params: .mlDsa65)
let valid = MlDsa.verify(pk: pk, message: messageBytes, sig: sig, params: .mlDsa65)
```

#### PHP

```php
use PQC\MlDsa\MlDsa;

$kp = MlDsa::keyGen(65);  // 44, 65, or 87
$sig = MlDsa::sign($kp['sk'], $message, 65);
$valid = MlDsa::verify($kp['pk'], $message, $sig, 65);
```

### Deterministic vs. Randomized Signing

ML-DSA supports both modes:

- **Randomized signing** (default): Incorporates fresh randomness (`rnd`) into the signing process, providing protection against side-channel attacks that exploit deterministic behavior.
- **Deterministic signing**: Set `rnd` to all zeros. Produces the same signature for the same key and message every time. Useful for testing and environments where randomness quality is uncertain.

This library uses randomized signing by default. Internal variants (`SignInternal`, `keyGenInternal`) accept explicit randomness for testing and KAT verification.

### Choosing a Parameter Set

- **ML-DSA-65**: Recommended for most applications. NIST Level 3 security.
- **ML-DSA-44**: Suitable when smaller keys/signatures are needed and Level 2 security suffices.
- **ML-DSA-87**: Use for maximum security (NIST Level 5).

---

## 5. SLH-DSA (FIPS 205) -- Hash-Based Signatures

### Overview

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) provides digital signatures whose security relies solely on the security of hash functions. Unlike ML-DSA, which relies on the hardness of lattice problems, SLH-DSA makes no additional computational assumptions beyond hash function collision and preimage resistance.

This makes SLH-DSA a conservative choice: even if lattice problems turn out to be easier than expected, SLH-DSA signatures remain secure as long as the underlying hash function is sound.

The tradeoff is size and speed. SLH-DSA signatures are significantly larger than ML-DSA signatures, and signing is slower.

### Parameter Sets

SLH-DSA defines 12 parameter sets across two axes:

- **Hash function**: SHA-2 or SHAKE
- **Security level**: 128, 192, or 256 bits
- **Size/speed tradeoff**: `s` (small signatures, slower) or `f` (fast signing, larger signatures)

| Parameter Set          | NIST Level | Public Key | Secret Key | Signature  |
|-----------------------|------------|------------|------------|------------|
| SLH-DSA-SHA2-128s     | 1          | 32 bytes   | 64 bytes   | 7,856 bytes  |
| SLH-DSA-SHA2-128f     | 1          | 32 bytes   | 64 bytes   | 17,088 bytes |
| SLH-DSA-SHAKE-128s    | 1          | 32 bytes   | 64 bytes   | 7,856 bytes  |
| SLH-DSA-SHAKE-128f    | 1          | 32 bytes   | 64 bytes   | 17,088 bytes |
| SLH-DSA-SHA2-192s     | 3          | 48 bytes   | 96 bytes   | 16,224 bytes |
| SLH-DSA-SHA2-192f     | 3          | 48 bytes   | 96 bytes   | 35,664 bytes |
| SLH-DSA-SHAKE-192s    | 3          | 48 bytes   | 96 bytes   | 16,224 bytes |
| SLH-DSA-SHAKE-192f    | 3          | 48 bytes   | 96 bytes   | 35,664 bytes |
| SLH-DSA-SHA2-256s     | 5          | 64 bytes   | 128 bytes  | 29,792 bytes |
| SLH-DSA-SHA2-256f     | 5          | 64 bytes   | 128 bytes  | 49,856 bytes |
| SLH-DSA-SHAKE-256s    | 5          | 64 bytes   | 128 bytes  | 29,792 bytes |
| SLH-DSA-SHAKE-256f    | 5          | 64 bytes   | 128 bytes  | 49,856 bytes |

### API Reference

The API is consistent across languages: `keygen`, `sign`, `verify` with a parameter set selector.

#### Rust

```rust
use slh_dsa::slhdsa::{keygen, sign, verify};
use slh_dsa::params::SlhDsaShake128f;
use slh_dsa::hash::ShakeHash;

let (sk, pk) = keygen::<SlhDsaShake128f, ShakeHash>(&mut rng);
let sig = sign::<SlhDsaShake128f, ShakeHash>(&sk, message, &mut rng);
let valid = verify::<SlhDsaShake128f, ShakeHash>(&pk, message, &sig);
```

#### Go

```go
import "github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"

// Parameter sets: slhdsa.SHAKE128s, SHAKE128f, SHA2_128s, SHA2_128f, etc.
pk, sk := slhdsa.KeyGen(slhdsa.SHAKE128f)
sig := slhdsa.Sign(sk, msg, slhdsa.SHAKE128f)
valid := slhdsa.Verify(pk, msg, sig, slhdsa.SHAKE128f)
```

#### Python

```python
from slhdsa import keygen, sign, verify
from slhdsa import SLH_DSA_SHAKE_128f, SLH_DSA_SHA2_128s  # 12 parameter sets

pk, sk = keygen(SLH_DSA_SHAKE_128f)
sig = sign(sk, message, SLH_DSA_SHAKE_128f)
assert verify(pk, message, sig, SLH_DSA_SHAKE_128f)
```

#### JavaScript

```js
import { keyGen, sign, verify, SLH_DSA_SHAKE_128f } from '@pqc/slh-dsa';

const { pk, sk } = keyGen(SLH_DSA_SHAKE_128f);
const sig = sign(sk, message, SLH_DSA_SHAKE_128f);
const valid = verify(pk, message, sig, SLH_DSA_SHAKE_128f);
```

#### Java

```java
import com.pqc.slhdsa.SLHDSA;
import com.pqc.slhdsa.SlhParams;

SLHDSA.KeyPair kp = SLHDSA.keyGen(SlhParams.SHAKE_128f);
byte[] sig = SLHDSA.sign(kp.sk(), msg, SlhParams.SHAKE_128f);
boolean valid = SLHDSA.verify(kp.pk(), msg, sig, SlhParams.SHAKE_128f);
```

#### C#

```csharp
using PqcStandards.SlhDsa;

var (pk, sk) = SlhDsaAlgorithm.KeyGen(SlhDsaParams.Shake128f);
var sig = SlhDsaAlgorithm.Sign(sk, message, SlhDsaParams.Shake128f);
bool valid = SlhDsaAlgorithm.Verify(pk, message, sig, SlhDsaParams.Shake128f);
```

#### Swift

```swift
let (pk, sk) = SlhDsa.keyGen(params: .shake128f)
let sig = SlhDsa.sign(sk: sk, message: messageBytes, params: .shake128f)
let valid = SlhDsa.verify(pk: pk, message: messageBytes, sig: sig, params: .shake128f)
```

#### PHP

```php
use PQC\SlhDsa\SlhDsa;

$kp = SlhDsa::keyGen('shake-128f');
$sig = SlhDsa::sign($kp['sk'], $message, 'shake-128f');
$valid = SlhDsa::verify($kp['pk'], $message, $sig, 'shake-128f');
```

### When to Use SLH-DSA vs. ML-DSA

| Consideration        | ML-DSA           | SLH-DSA               |
|---------------------|------------------|------------------------|
| Security basis      | Lattice problems | Hash functions only    |
| Signature size      | ~2.4-4.6 KB      | ~7.8-49.9 KB          |
| Public key size     | ~1.3-2.6 KB      | 32-64 bytes            |
| Signing speed       | Fast             | Slow (especially `s`)  |
| Verification speed  | Fast             | Moderate               |
| Conservative choice | No               | Yes                    |

**Primary recommendation:** Use ML-DSA-65 as your default signature scheme. Use SLH-DSA as a backup/hedge if you want defense-in-depth against potential lattice algorithm breakthroughs, or in contexts where conservative security assumptions are paramount.

### Choosing a Parameter Set

- **SHAKE-128f**: Best for speed when signature size is not critical.
- **SHA2-128s**: Smallest signatures at the 128-bit security level.
- **SHAKE-256s / SHA2-256s**: Maximum security with smallest signatures for that level.
- **SHA-2 variants**: Preferred when hardware acceleration for SHA-2 is available.
- **SHAKE variants**: Preferred when SHAKE/Keccak hardware acceleration is available.

---

## 6. Hybrid KEMs

### Why Hybrids

Hybrid key encapsulation combines a classical (pre-quantum) key exchange with a post-quantum KEM. The resulting shared secret is secure as long as **either** component remains unbroken. This provides a safety net during the transition period:

- If quantum computers arrive sooner than expected, the PQ component protects you.
- If the PQ algorithm has an unexpected weakness, the classical component protects you.

Hybrid KEMs are recommended by multiple standards bodies for the transition period, and are already deployed in TLS (Chrome, Cloudflare, and others use X25519+ML-KEM-768).

### Supported Schemes

| Scheme                  | Classical | Post-Quantum  | Security | Use Case          |
|------------------------|-----------|---------------|----------|-------------------|
| X25519+ML-KEM-768      | X25519    | ML-KEM-768    | ~128-bit | TLS, general use  |
| ECDH-P256+ML-KEM-768   | P-256     | ML-KEM-768    | ~128-bit | NIST curve users  |
| X25519+ML-KEM-1024     | X25519    | ML-KEM-1024   | ~192-bit | Higher security   |
| ECDH-P384+ML-KEM-1024  | P-384     | ML-KEM-1024   | ~192-bit | High security     |

### KEM Combiner

The shared secret is derived by hashing together both component secrets with a label:

```
combined_ss = SHA3-256(ss_classical || ss_pq || label)
```

This ensures the combined secret depends on both components.

### API Reference

#### Go

```go
import "github.com/liviuepure/PQC-Standards-Implementation/go/hybrid"

// Schemes: hybrid.X25519MlKem768, EcdhP256MlKem768, X25519MlKem1024, EcdhP384MlKem1024
kp, err := hybrid.KeyGen(hybrid.X25519MlKem768, rand.Reader)
// kp.EK = classical_pk || pq_ek
// kp.DK = classical_sk || pq_dk

result, err := hybrid.Encaps(hybrid.X25519MlKem768, kp.EK, kp.ClassicalEKSize, rand.Reader)
// result.SharedSecret = [32]byte
// result.Ciphertext = classical_ct || pq_ct

recovered, err := hybrid.Decaps(hybrid.X25519MlKem768, kp.DK, result.Ciphertext,
    kp.ClassicalDKSize, result.ClassicalCTSize)
```

#### Python

```python
from hybrid import (
    hybrid_keygen, hybrid_encaps, hybrid_decaps,
    X25519_MLKEM768, ECDHP256_MLKEM768,
    X25519_MLKEM1024, ECDHP384_MLKEM1024,
)

keys = hybrid_keygen(X25519_MLKEM768)
enc = hybrid_encaps(X25519_MLKEM768, keys)
ss = hybrid_decaps(X25519_MLKEM768, keys, enc)
```

#### Rust

```rust
use hybrid_kem::{X25519MlKem768, HybridKemScheme};

let kp = X25519MlKem768::keygen(&mut rng);
let enc = X25519MlKem768::encapsulate(&kp.ek, &mut rng);
let recovered = X25519MlKem768::decapsulate(&kp.dk, &enc.ciphertext);
```

#### JavaScript

```js
import { hybridKeyGen, hybridEncaps, hybridDecaps, X25519_MLKEM768 } from '@pqc/hybrid';

const kp = hybridKeyGen(X25519_MLKEM768);
const enc = hybridEncaps(X25519_MLKEM768, kp);
const ss = hybridDecaps(X25519_MLKEM768, kp, enc);
```

**Recommendation:** Use **X25519+ML-KEM-768** for most applications. It is the standard hybrid for TLS 1.3 and combines the well-studied X25519 with the recommended ML-KEM-768.

---

## 7. Composite Signatures

### Why Composites

Composite signatures apply the hybrid principle to digital signatures: a message is signed with both a classical algorithm (Ed25519 or ECDSA-P256) and a post-quantum algorithm (ML-DSA). Verification requires **both** signatures to be valid.

This provides dual protection: if either the classical or the PQ scheme is broken, the composite signature still cannot be forged as long as the other component is secure.

### Supported Schemes

| Scheme                  | Classical   | Post-Quantum | Security | Recommended |
|------------------------|-------------|-------------|----------|-------------|
| ML-DSA-65+Ed25519      | Ed25519     | ML-DSA-65   | Level 3  | Yes         |
| ML-DSA-65+ECDSA-P256   | ECDSA-P256  | ML-DSA-65   | Level 3  | NIST curves |
| ML-DSA-87+Ed25519      | Ed25519     | ML-DSA-87   | Level 5  | High sec    |
| ML-DSA-44+Ed25519      | Ed25519     | ML-DSA-44   | Level 2  | Constrained |

### Wire Format

Composite signatures use a simple length-prefixed format:

```
composite_sig = len(sig_classical) [4 bytes, little-endian] || sig_classical || sig_pq
```

For ML-DSA-65+Ed25519, a composite signature is 4 + 64 + 3309 = 3377 bytes.

Composite public keys are concatenated: `pk_classical || pk_pq`.

### API Reference

#### Go

```go
import "github.com/liviuepure/PQC-Standards-Implementation/go/composite"

// Schemes: composite.MlDsa65Ed25519, MlDsa65EcdsaP256, MlDsa87Ed25519, MlDsa44Ed25519
kp := composite.KeyGen(composite.MlDsa65Ed25519)
sig := composite.Sign(kp, []byte("hello world"))
valid := composite.Verify(composite.MlDsa65Ed25519, kp.PK, []byte("hello world"), sig)

// Parse signature components
classicalSig, pqSig, err := composite.ParseSig(sig)
```

#### Python

```python
from composite import (
    key_gen, sign, verify,
    MLDSA65_ED25519, MLDSA65_ECDSA_P256,
    MLDSA87_ED25519, MLDSA44_ED25519,
)

pk, sk = key_gen(MLDSA65_ED25519)
sig = sign(sk, b"hello world", MLDSA65_ED25519)
assert verify(pk, b"hello world", sig, MLDSA65_ED25519)
```

#### Rust

```rust
use composite_sig::{MLDSA65_ED25519, CompositeScheme};

let kp = MLDSA65_ED25519::keygen(&mut rng);
let sig = MLDSA65_ED25519::sign(&kp, b"hello world");
let valid = MLDSA65_ED25519::verify(&kp.pk, b"hello world", &sig);
```

#### JavaScript

```js
import { keyGen, sign, verify, MLDSA65_ED25519 } from '@pqc/composite';

const kp = keyGen(MLDSA65_ED25519);
const sig = sign(kp, message);
const valid = verify(MLDSA65_ED25519, kp.pk, message, sig);
```

#### Java

```java
import com.pqc.composite.CompositeSig;

CompositeSig.KeyPair kp = CompositeSig.keyGen(CompositeSig.MLDSA65_ED25519);
byte[] sig = CompositeSig.sign(kp, msg);
boolean valid = CompositeSig.verify(CompositeSig.MLDSA65_ED25519, kp.pk(), msg, sig);
```

**Recommendation:** Use **ML-DSA-65+Ed25519** for most applications. Ed25519 is widely deployed, fast, and pairs well with ML-DSA-65 at NIST Level 3.

---

## 8. TLS 1.3 Integration

This library provides the cryptographic building blocks needed to add post-quantum key exchange and authentication to TLS 1.3 handshakes. It is **not** a full TLS implementation, but rather the primitives that plug into existing TLS libraries.

### Named Groups (Key Exchange)

These are used in the `supported_groups` extension and `key_share` entries:

| Named Group          | Code Point | Description                    |
|---------------------|------------|--------------------------------|
| MLKEM768            | 0x0768     | Pure ML-KEM-768                |
| MLKEM1024           | 0x1024     | Pure ML-KEM-1024               |
| X25519MLKEM768      | 0x6399     | X25519 + ML-KEM-768 hybrid     |
| SecP256r1MLKEM768   | 0x639A     | P-256 + ML-KEM-768 hybrid      |

### Signature Algorithms (CertificateVerify)

| Algorithm           | Code Point | Description                    |
|---------------------|------------|--------------------------------|
| MLDSA44             | 0x0904     | ML-DSA-44                      |
| MLDSA65             | 0x0905     | ML-DSA-65                      |
| MLDSA87             | 0x0906     | ML-DSA-87                      |
| MLDSA65_ED25519     | 0x0907     | ML-DSA-65 + Ed25519 composite  |
| MLDSA87_ED25519     | 0x0908     | ML-DSA-87 + Ed25519 composite  |

### Cipher Suites

| Suite ID | Name                                    |
|----------|-----------------------------------------|
| 0x1301   | TLS_AES_128_GCM_SHA256 + ML-KEM-768    |
| 0x1302   | TLS_AES_256_GCM_SHA384 + X25519MLKEM768|

### Using the Key Share Helpers

The TLS integration layer provides three functions that map to the TLS 1.3 handshake flow:

#### Step 1: Client generates a key share

```go
import "github.com/liviuepure/PQC-Standards-Implementation/go/pqctls"

// Client: generate key share for ClientHello
ks, err := pqctls.GenerateKeyShare(pqctls.X25519MLKEM768, rand.Reader)
// Send ks.PublicKeyShare in ClientHello key_share extension
// Keep ks.PrivateKey, ks.ClassicalEKSize, ks.ClassicalDKSize for later
```

#### Step 2: Server completes the exchange

```go
// Server: complete key exchange using client's key share
result, err := pqctls.CompleteKeyExchange(
    pqctls.X25519MLKEM768,
    clientKeyShare,       // from ClientHello
    classicalEKSize,      // boundary info
    rand.Reader,
)
// result.SharedSecret = [32]byte (use for key derivation)
// Send result.ResponseKeyShare in ServerHello key_share
```

#### Step 3: Client recovers the shared secret

```go
// Client: recover shared secret using server's response
ss, err := pqctls.RecoverSharedSecret(
    pqctls.X25519MLKEM768,
    privateKey,           // from Step 1
    serverResponse,       // from ServerHello
    classicalDKSize,
    classicalCTSize,
)
// ss matches result.SharedSecret from Step 2
```

#### Python equivalent

```python
from pqctls import generate_key_share, complete_key_exchange, recover_shared_secret
from pqctls import NamedGroup

# Client
ks = generate_key_share(NamedGroup.X25519MLKEM768)
# Server
result = complete_key_exchange(NamedGroup.X25519MLKEM768, ks.public_key_share, ks.classical_ek_size)
# Client
ss = recover_shared_secret(NamedGroup.X25519MLKEM768, ks.private_key, result.response_key_share,
                           ks.classical_dk_size, result.classical_ct_size)
```

### Integration with Existing TLS Libraries

To integrate with an existing TLS library:

1. Register the PQC named groups in the library's supported groups list.
2. Use `GenerateKeyShare` to produce key share bytes for the ClientHello/ServerHello.
3. Use `CompleteKeyExchange` / `RecoverSharedSecret` for the server/client sides.
4. Feed the resulting 32-byte shared secret into the TLS key schedule (HKDF-Extract / Derive-Secret) as you would with any other key exchange result.

---

## 9. Parameter Set Selection Guide

Use the following decision tree to select the right algorithms:

```
Do you need key exchange or key transport?
|
+-- Yes --> Are you in a transition period (need backward compatibility)?
|           |
|           +-- Yes --> Use Hybrid X25519+ML-KEM-768
|           |
|           +-- No  --> Use ML-KEM-768 (pure PQ)
|
Do you need digital signatures?
|
+-- Yes --> Do you need backward compatibility with classical verifiers?
|           |
|           +-- Yes --> Use Composite ML-DSA-65+Ed25519
|           |
|           +-- No  --> Do you need conservative security assumptions?
|           |           |
|           |           +-- Yes --> Use SLH-DSA (SHAKE-128f for speed, SHA2-128s for size)
|           |           |
|           |           +-- No  --> Use ML-DSA-65
|           |
|           +-- Maximum security needed?
|                       |
|                       +-- Yes --> ML-DSA-87 or SLH-DSA-256s
|
Is bandwidth severely constrained?
|
+-- Yes --> ML-KEM-768 + ML-DSA-65 (smallest PQ option with good security)
|
+-- No  --> ML-KEM-768 + ML-DSA-65 (still the best default)

Maximum security profile:
    ML-KEM-1024 + ML-DSA-87 + SLH-DSA-256s (as backup)
```

### Summary Table

| Scenario                     | Key Exchange          | Signatures            |
|-----------------------------|----------------------|----------------------|
| General purpose             | ML-KEM-768           | ML-DSA-65            |
| TLS 1.3 transition          | X25519+ML-KEM-768    | ML-DSA-65+Ed25519    |
| Maximum security            | ML-KEM-1024          | ML-DSA-87            |
| Conservative (hash-only)    | --                   | SLH-DSA-SHAKE-128f   |
| Bandwidth constrained       | ML-KEM-768           | ML-DSA-44            |
| Long-term document signing  | --                   | SLH-DSA-SHA2-256s    |

---

## 10. Security Considerations

### Constant-Time Implementations

All secret-dependent operations in this library use constant-time algorithms to prevent timing side-channel attacks:

- **Rust**: Uses the `subtle` crate for constant-time comparisons and conditional selections. No branching on secret data.
- **Go**: Uses `crypto/subtle.ConstantTimeCompare` and `ConstantTimeSelect`.
- **JavaScript**: Uses `crypto.timingSafeEqual` from Node.js and manual constant-time select loops.
- **Python**: Uses `hmac.compare_digest` for constant-time comparison.
- **Java/C#/Swift/PHP**: Use timing-safe comparison utilities from their respective standard libraries.

### Implicit Rejection (ML-KEM)

When ML-KEM decapsulation detects a tampered ciphertext (the re-encrypted ciphertext does not match the input), it does **not** return an error. Instead, it returns a pseudorandom value derived from the secret key and the ciphertext: `J(z || ct)`. This is called implicit rejection.

This design prevents decryption oracle attacks where an adversary could distinguish between valid and invalid ciphertexts based on error messages.

### Side-Channel Resistance

While all implementations aim for constant-time behavior, be aware that:

- Pure software implementations in managed languages (Python, JS, PHP) cannot fully guarantee constant-time execution due to interpreter behavior, garbage collection, and JIT compilation.
- For high-security environments, prefer Rust or Go implementations.
- The Rust implementation uses `#![forbid(unsafe_code)]` and relies on the `subtle` crate, which is specifically designed for cryptographic constant-time operations.

### Random Number Generation

All implementations use cryptographically secure random number generators:

- **Rust**: Caller provides a `CryptoRng + RngCore` (typically `OsRng`).
- **Go**: `crypto/rand.Reader` (or caller-provided `io.Reader`).
- **JavaScript**: `crypto.randomBytes` from Node.js.
- **Python**: `os.urandom`.
- **Java**: `java.security.SecureRandom`.
- **C#**: `System.Security.Cryptography.RandomNumberGenerator`.
- **Swift**: `SystemRandomNumberGenerator`.
- **PHP**: `random_bytes`.

Never substitute a non-cryptographic RNG. The security of all algorithms depends on high-quality randomness.

### Key Storage and Lifecycle

- **Decapsulation keys** and **signing secret keys** must be stored securely and protected from unauthorized access.
- Zeroize secret keys from memory when no longer needed. The Rust implementation uses the `zeroize` crate for this purpose.
- ML-KEM encapsulation keys and ML-DSA public keys can be freely distributed.
- Do not reuse ML-KEM key pairs across different protocols without careful analysis.

### Not FIPS-Validated

This implementation follows the FIPS 203/204/205 specifications precisely and passes all known-answer tests (KATs). However, it has **not** undergone FIPS validation through the NIST Cryptographic Module Validation Program (CMVP). If your compliance requirements mandate FIPS-validated modules, you must use a certified implementation.

---

## 11. Migration Guide

### From RSA/ECDH to ML-KEM or Hybrid KEMs

**Phase 1: Hybrid deployment**

Replace classical key exchange with hybrid:

```
Before: ECDH (X25519 or P-256) -> shared_secret
After:  X25519+ML-KEM-768      -> combined_shared_secret
```

In TLS, this means advertising `X25519MLKEM768` (code point 0x6399) in your supported groups. Servers that support it will negotiate the hybrid; others fall back to classical X25519.

**Phase 2: Pure PQ**

Once the transition is mature and classical fallback is no longer needed:

```
After:  ML-KEM-768 -> shared_secret
```

### From RSA/ECDSA to ML-DSA or Composite Signatures

**Phase 1: Composite signatures**

Use composite signatures during the transition:

```
Before: Ed25519 signature
After:  ML-DSA-65+Ed25519 composite signature
```

Legacy verifiers that only understand Ed25519 can verify the classical component. New verifiers check both.

**Phase 2: Pure PQ signatures**

```
After:  ML-DSA-65 signature
```

### Recommended Migration Timeline (CNSA 2.0 Alignment)

The NSA's CNSA 2.0 guidance recommends:

| Capability                  | Transition Start | Exclusive PQ By |
|----------------------------|-----------------|-----------------|
| Software/firmware signing  | Immediately      | 2030            |
| Web servers/browsers (TLS) | Immediately      | 2033            |
| Networking equipment       | 2025             | 2030            |
| Operating systems, VPNs    | 2025             | 2030            |

### Backward Compatibility Strategies

1. **Negotiate both**: In TLS, advertise both classical and PQ/hybrid named groups. The negotiation selects the strongest mutually supported option.
2. **Dual certificates**: Issue certificates with both classical and PQ signatures during transition.
3. **Composite mode**: Use composite signatures where verifiers might only support one component.
4. **Feature detection**: Check peer capability before selecting PQ algorithms.

---

## 12. Building and Testing

### Rust

```bash
# Add to your Cargo.toml
[dependencies]
ml-kem = { path = "rust/ml-kem" }
ml-dsa = { path = "rust/ml-dsa" }
slh-dsa = { path = "rust/slh-dsa" }
hybrid-kem = { path = "rust/hybrid-kem" }
composite-sig = { path = "rust/composite-sig" }
pqc-tls = { path = "rust/pqc-tls" }

# Or use the workspace
cd rust
cargo build --release
cargo test
cargo bench  # Run benchmarks (ml-kem)
```

Workspace features:
- `no_std` support (all core crates)
- `alloc` feature for heap-using functionality
- Minimum Rust version: 1.75

### Go

```bash
# Add to your project
go get github.com/liviuepure/PQC-Standards-Implementation/go@latest

# Import specific packages
import "github.com/liviuepure/PQC-Standards-Implementation/go/mlkem"
import "github.com/liviuepure/PQC-Standards-Implementation/go/mldsa"
import "github.com/liviuepure/PQC-Standards-Implementation/go/slhdsa"
import "github.com/liviuepure/PQC-Standards-Implementation/go/hybrid"
import "github.com/liviuepure/PQC-Standards-Implementation/go/composite"
import "github.com/liviuepure/PQC-Standards-Implementation/go/pqctls"

# Run tests
cd go
go test ./...
```

Requires Go 1.22+. External dependency: `golang.org/x/crypto` (for SHA-3 and X25519).

### JavaScript (Node.js)

```bash
# Install
cd js
npm install

# Use in your project (ESM)
import { keyGen, encaps, decaps, ML_KEM_768 } from '@pqc/ml-kem';

# Run tests
npm test
```

Requires Node.js 20+ (for `node:crypto` with `timingSafeEqual` and `node --test`). No external dependencies.

### Python

```bash
# Install (from source)
cd python

# Use in your project
import sys
sys.path.insert(0, '/path/to/PQC-Standards-Implementation/python')

from mlkem import keygen, encaps, decaps, ML_KEM_768
from mldsa import keygen, sign, verify, ML_DSA_65
from slhdsa import keygen, sign, verify, SLH_DSA_SHAKE_128f
from hybrid import hybrid_keygen, hybrid_encaps, hybrid_decaps, X25519_MLKEM768
from composite import key_gen, sign, verify, MLDSA65_ED25519
from pqctls import generate_key_share, complete_key_exchange, recover_shared_secret

# Run tests
python -m pytest tests/
```

Requires Python 3.10+. No external dependencies (uses only the standard library).

### Java

```bash
# Build with Maven
cd java
mvn compile

# Run tests
mvn test

# Use in your project (Maven)
<dependency>
    <groupId>com.pqc</groupId>
    <artifactId>pqc-standards</artifactId>
    <version>0.1.0</version>
</dependency>
```

Requires Java 17+. No external runtime dependencies (JUnit 5 for tests only).

### C# (.NET)

```bash
# Build
cd dotnet
dotnet build

# Run tests
dotnet test

# Add to your project
dotnet add reference src/PqcStandards/PqcStandards.csproj

# Or use as NuGet package reference
<PackageReference Include="PqcStandards" Version="0.1.0" />
```

Requires .NET 10.0+.

### Swift

```bash
# Build
cd swift
swift build

# Run tests
swift test

# Add to your Package.swift
dependencies: [
    .package(url: "https://github.com/liviuepure/PQC-Standards-Implementation", from: "0.1.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "PQCStandards", package: "PQC-Standards-Implementation"),
        ]
    ),
]
```

Requires Swift 5.9+, macOS 13+ / iOS 16+. No external dependencies.

### PHP

```bash
# Install dependencies
cd php
composer install

# Use in your project
composer require pqc/standards

# Or add to composer.json
{
    "require": {
        "pqc/standards": "^0.1"
    }
}

# Run tests
./vendor/bin/phpunit tests/
```

Requires PHP 8.1+. PSR-4 autoloading via Composer.

### Cross-Language Interoperability Suite

A full cross-language test suite verifies that all language implementations produce identical output for the same inputs.

**Run the suite (from repo root):**
```bash
bash interop/run_interop_comprehensive.sh
```

This script:
1. Uses Python to generate test vectors for 12 schemes (ML-KEM×3, ML-DSA×3, SLH-DSA-SHAKE×6)
2. Runs verifiers in all 8 languages against those vectors in parallel
3. Writes `interop_results.json` and `interop_results.txt` with per-language pass/fail results

**Result: 96/96 PASS** — all 8 languages, all 12 schemes.

**Generate extended test vectors (all 27 schemes including hybrid, composite, TLS):**
```bash
cd go && go run ./cmd/generate-all-vectors ../test-vectors
python3 interop/generate_all_results.py
```

This produces `interop_results_all.json` and `interop_results_all.txt` covering:
- ML-KEM (3 variants) × 8 languages = 24 tests
- ML-DSA (3 variants) × 8 languages = 24 tests
- SLH-DSA SHAKE (6 variants) × 8 languages = 48 tests
- SLH-DSA SHA2 (6 variants), Go self-test
- Hybrid KEM (4 variants), Go self-test
- Composite Signatures (4 variants), Go self-test
- PQ-TLS key exchange, Go self-test

**Total: 111/111 PASS**

Test vector format (example `test-vectors/ml-kem/ML-KEM-768.json`):
```json
{
  "algorithm": "ML-KEM-768",
  "generated_by": "Go reference (FIPS 203)",
  "ek": "...",
  "dk": "...",
  "ct": "...",
  "ss": "..."
}
```

---

## 13. Performance

### Benchmark Overview

The following tables show approximate operation times. Actual performance varies significantly by hardware, compiler, and runtime. These numbers are from a modern ARM64 processor.

#### ML-KEM Operation Times

| Operation  | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| KeyGen    | ~30 us     | ~50 us     | ~75 us      |
| Encaps    | ~35 us     | ~55 us     | ~85 us      |
| Decaps    | ~40 us     | ~60 us     | ~90 us      |

(Rust/Go timings. Python/JS/PHP will be 100-1000x slower due to interpreter overhead.)

#### ML-DSA Operation Times

| Operation  | ML-DSA-44  | ML-DSA-65  | ML-DSA-87  |
|-----------|------------|------------|------------|
| KeyGen    | ~100 us    | ~170 us    | ~250 us    |
| Sign      | ~400 us    | ~700 us    | ~900 us    |
| Verify    | ~110 us    | ~180 us    | ~260 us    |

(Sign times are averages; the rejection sampling loop introduces variance.)

#### SLH-DSA Operation Times

| Operation  | SHAKE-128f  | SHAKE-128s  | SHAKE-256f  | SHAKE-256s  |
|-----------|-------------|-------------|-------------|-------------|
| KeyGen    | ~1 ms       | ~8 ms       | ~2 ms       | ~20 ms      |
| Sign      | ~15 ms      | ~200 ms     | ~40 ms      | ~500 ms     |
| Verify    | ~1 ms       | ~3 ms       | ~2 ms       | ~8 ms       |

SLH-DSA is orders of magnitude slower than ML-DSA, especially the `s` (small) variants.

### Relative Language Performance

| Language | Relative Speed (ML-KEM-768 roundtrip) |
|----------|--------------------------------------|
| Rust     | 1x (baseline)                        |
| Go       | ~1.5-2x slower                       |
| Java     | ~2-4x slower                         |
| C#       | ~2-4x slower                         |
| Swift    | ~2-5x slower                         |
| JS       | ~50-200x slower                      |
| Python   | ~200-500x slower                     |
| PHP      | ~200-500x slower                     |

### Optimization Tips

1. **Use Rust or Go** for performance-critical applications (servers, high-throughput signing).
2. **Batch operations** when possible. Key generation can be done in advance.
3. **Pre-compute NTT forms** of matrix A for repeated signing with the same key (the library does this internally).
4. **Choose `f` variants of SLH-DSA** when signing speed matters more than signature size.
5. **Avoid SLH-DSA in latency-sensitive paths** unless you specifically need hash-based security guarantees.
6. For **Python/JS/PHP**, these implementations are best suited for testing, prototyping, and low-throughput use. For production servers, use the Rust or Go implementations.

---

## 14. FAQ

### Is this FIPS-validated?

No. This implementation follows the FIPS 203/204/205 specifications and passes all published known-answer test vectors, but it has not been submitted for FIPS validation through the CMVP. If you need a FIPS-validated module, use one that has been certified.

### Can I use this in production?

Yes, with the understanding that:
- It is not FIPS-validated (see above).
- The interpreted language implementations (Python, JS, PHP) have limited side-channel resistance.
- You should keep up to date with any errata or updates to the FIPS standards.
- The Rust and Go implementations are the most suitable for production use.

### What about FN-DSA (FALCON)?

FALCON is expected to become FIPS 206, but the standard has not been finalized as of early 2026. FN-DSA offers smaller signatures than ML-DSA at the cost of more complex implementation (floating-point arithmetic, careful sampling). This library does not yet include FN-DSA. It will be added when the standard is published.

### What about HQC?

HQC (Hamming Quasi-Cyclic) was selected as a backup KEM by NIST, providing a code-based alternative to the lattice-based ML-KEM. Standardization is still in progress. This library does not yet include HQC.

### Are the implementations interoperable across languages?

Yes, and this has been verified. The cross-language interop suite achieves **96/96 PASS** across Python, Go, Java, JavaScript, Rust, Swift, .NET, and PHP for all 12 schemes (ML-KEM×3, ML-DSA×3, SLH-DSA-SHAKE×6).

You can generate a key pair in Rust, encapsulate in Python, and decapsulate in Go — the shared secrets match. The `test-vectors/` directory contains JSON vector files for all 27 schemes (including hybrid KEM, composite signatures, and PQ-TLS) that any language can load and verify against.

Run the suite:
```bash
bash interop/run_interop_comprehensive.sh
```

Several interoperability bugs were found and fixed during this testing:
- PHP WOTS+ checksum byte endianness (big-endian prepend → append)
- PHP/Java/C# arithmetic right shift for 64-bit tree indices in SLH-DSA
- .NET wrong Keccak-f[1600] PiLane permutation (fixed all SHA3/SHAKE operations)
- Swift ML-KEM wrong shared secret formula (extra SHA3-256 wrapping removed)
- Java SLH-DSA parameter set values (all 12 sets had wrong `hPrime`, `d`, `a` fields)

### How large are the keys and signatures compared to classical algorithms?

| Algorithm    | Public Key | Private Key | Signature / Ciphertext |
|-------------|------------|-------------|----------------------|
| RSA-2048    | 256 bytes  | ~1200 bytes | 256 bytes            |
| ECDSA-P256  | 64 bytes   | 32 bytes    | 64 bytes             |
| Ed25519     | 32 bytes   | 64 bytes    | 64 bytes             |
| X25519      | 32 bytes   | 32 bytes    | 32 bytes (shared)    |
| ML-KEM-768  | 1184 bytes | 2400 bytes  | 1088 bytes (ct)      |
| ML-DSA-65   | 1952 bytes | 4032 bytes  | 3309 bytes           |
| SLH-DSA-128f| 32 bytes   | 64 bytes    | 17,088 bytes         |

Post-quantum algorithms require significantly larger keys and signatures. This is the fundamental tradeoff for quantum resistance.

### Can I use ML-KEM as a drop-in replacement for ECDH?

Not quite. ML-KEM is a KEM (key encapsulation mechanism), not a key exchange. The difference:

- **ECDH**: Both parties contribute a public key, and the shared secret is derived from both.
- **KEM**: One party generates a key pair, the other encapsulates. Only the key pair holder can decapsulate.

In TLS 1.3, this maps naturally to the key_share mechanism, and the library's TLS integration layer handles the adaptation.

### What about multi-party or threshold variants?

This library implements only the standard single-party algorithms defined in FIPS 203/204/205. Threshold or multi-party variants are not included.

---

## 15. License

This project is released under the **MIT License**.

```
MIT License

Copyright (c) 2026 Liviu Epure

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
