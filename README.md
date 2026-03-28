# PQC Standards Implementation

Pure implementations of NIST Post-Quantum Cryptography standards across 8 programming languages, with full cross-language interoperability verified by a shared test vector suite.

## Standards

| Standard | Algorithm | Type | Status |
|----------|-----------|------|--------|
| **FIPS 203** | ML-KEM (Kyber) | Key Encapsulation | ✅ 8 languages |
| **FIPS 204** | ML-DSA (Dilithium) | Digital Signature | ✅ 8 languages |
| **FIPS 205** | SLH-DSA (SPHINCS+) SHAKE | Hash-Based Signature | ✅ 8 languages |
| **FIPS 205** | SLH-DSA SHA2 variants | Hash-Based Signature | ✅ Go |
| Hybrid KEM | X25519+ML-KEM, ECDH+ML-KEM | Hybrid Key Exchange | ✅ Go |
| Composite Sig | ML-DSA + Ed25519/ECDSA | Hybrid Signatures | ✅ Go |
| PQ-TLS 1.3 | Named Groups + Cipher Suites | Protocol Integration | ✅ Go |

## Cross-Language Interoperability Results

**96 / 96 PASS** — Python, Go, Java, JavaScript, Rust, Swift, .NET, PHP

| Algorithm | Parameter Set | Py | Go | Java | JS | Rust | Swift | .NET | PHP |
|-----------|--------------|----|----|------|----|------|-------|------|-----|
| ML-KEM | ML-KEM-512 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-KEM | ML-KEM-768 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-KEM | ML-KEM-1024 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA | ML-DSA-44 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA | ML-DSA-65 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ML-DSA | ML-DSA-87 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SLH-DSA | SHAKE-128f/s | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SLH-DSA | SHAKE-192f/s | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SLH-DSA | SHAKE-256f/s | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Full results: [`interop_results.json`](interop_results.json) · [`interop_results_all.json`](interop_results_all.json) · [`interop_results_all.txt`](interop_results_all.txt)

Run the suite yourself:
```bash
bash interop/run_interop_comprehensive.sh
```

## Quick Start

```go
// Go — ML-KEM key exchange
ek, dk, _ := mlkem.KeyGen(params.MlKem768, rand.Reader)
ss, ct, _ := mlkem.Encapsulate(params.MlKem768, ek, rand.Reader)
recovered := mlkem.Decapsulate(params.MlKem768, dk, ct)
```

```python
# Python — ML-DSA signing
from mldsa import keygen, sign, verify, ML_DSA_65
pk, sk = keygen(ML_DSA_65)
sig = sign(sk, b"hello", ML_DSA_65)
assert verify(pk, b"hello", sig, ML_DSA_65)
```

See [`MANUAL.md`](MANUAL.md) for complete API reference in all 8 languages.

## Repository Structure

```
PQC-Standards-Implementation/
├── rust/                   # Rust implementations
├── go/                     # Go implementations
│   ├── mlkem/              # ML-KEM (FIPS 203)
│   ├── mldsa/              # ML-DSA (FIPS 204)
│   ├── slhdsa/             # SLH-DSA (FIPS 205, SHAKE + SHA2)
│   ├── hybrid/             # Hybrid KEMs (X25519+ML-KEM, ECDH+ML-KEM)
│   ├── composite/          # Composite Signatures (ML-DSA + Ed25519/ECDSA)
│   ├── pqctls/             # PQ-TLS 1.3 named groups and cipher suites
│   └── cmd/
│       ├── generate-all-vectors/  # Test vector generator
│       └── interop-verify/        # Cross-language verifier
├── js/                     # JavaScript (ES modules, Node.js 20+)
├── python/                 # Python 3.10+
├── java/                   # Java 17+, Maven
├── dotnet/                 # C#/.NET 10+
├── swift/                  # Swift 5.9+, CryptoKit
├── php/                    # PHP 8.1+
├── interop/                # Cross-language test infrastructure
│   ├── run_interop_comprehensive.sh   # Orchestrator (runs all 8 languages)
│   ├── interop_generate.py            # Python vector generator
│   ├── interop_verify_go.go           # Go verifier
│   ├── interop_verify_java.java       # Java verifier
│   ├── interop_verify_js.mjs          # JavaScript verifier
│   ├── interop_verify_php.php         # PHP verifier
│   ├── generate_all_vectors.go        # Extended vector generator
│   ├── generate_all_results.py        # Comprehensive results builder
│   └── vectors/
│       ├── *.json                     # Cross-language interop vectors (12 schemes)
│       └── all/                       # All 27 schemes (incl. hybrid, composite, TLS)
├── test-vectors/           # Test vectors by algorithm family
│   ├── ml-kem/             # ML-KEM-512, ML-KEM-768, ML-KEM-1024
│   ├── ml-dsa/             # ML-DSA-44, ML-DSA-65, ML-DSA-87
│   ├── slh-dsa/
│   │   ├── shake/          # SLH-DSA-SHAKE-{128,192,256}{f,s}
│   │   └── sha2/           # SLH-DSA-SHA2-{128,192,256}{f,s}
│   ├── hybrid-kem/         # X25519+ML-KEM-768/1024, ECDH-P256/P384+ML-KEM
│   ├── composite-sig/      # ML-DSA-{44,65,87}+Ed25519, ML-DSA-65+ECDSA-P256
│   └── pq-tls/             # PQ-TLS 1.3 X25519MLKEM768 key exchange
├── interop_results.json        # Cross-language results (96/96 PASS)
├── interop_results_all.json    # All schemes (111/111 PASS)
└── interop_results_all.txt     # Human-readable table
```

## Test Vectors

Test vectors are stored in `test-vectors/` organized by algorithm family. Each JSON file includes keys, ciphertext or signature, and is self-verified at generation time.

| Directory | Schemes | Format |
|-----------|---------|--------|
| `test-vectors/ml-kem/` | ML-KEM-512, 768, 1024 | `{ek, dk, ct, ss}` |
| `test-vectors/ml-dsa/` | ML-DSA-44, 65, 87 | `{pk, sk, msg, sig}` |
| `test-vectors/slh-dsa/shake/` | SHAKE-128f/s, 192f/s, 256f/s | `{pk, sk, msg, sig}` |
| `test-vectors/slh-dsa/sha2/` | SHA2-128f/s, 192f/s, 256f/s | `{pk, sk, msg, sig}` |
| `test-vectors/hybrid-kem/` | 4 hybrid schemes | `{ek, dk, ct, ss, *_size}` |
| `test-vectors/composite-sig/` | 4 composite schemes | `{pk, sk, msg, sig}` |
| `test-vectors/pq-tls/` | X25519MLKEM768 key exchange | named groups, cipher suites, key exchange |

Generate fresh vectors:
```bash
cd go && go run ./cmd/generate-all-vectors ../test-vectors
```

## Bugs Fixed (Interoperability)

During cross-language testing, the following implementation bugs were found and fixed:

| Language | Component | Bug | Fix |
|----------|-----------|-----|-----|
| PHP | SLH-DSA WOTS+ | Checksum bytes little-endian (wrong prepend loop) | Changed to append loop for big-endian |
| PHP | SLH-DSA Hypertree | Arithmetic right shift for 64-bit tree index | Unsigned shift with `PHP_INT_MAX` mask |
| .NET | All (SHA3/SHAKE) | Wrong Keccak-f[1600] PiLane permutation table | Corrected to FIPS 202 formula |
| .NET | SLH-DSA Hypertree | Arithmetic right shift for 64-bit tree index | Used C# 11+ `>>>` operator |
| Swift | ML-KEM | Wrong shared secret: `SHA3-256(K̄ ‖ H(ct))` | Return `K̄` directly per FIPS 203 |
| Swift | ML-KEM | Wrong implicit rejection: `SHA3-256(z ‖ H(ct))` | Use `J(z ‖ ct)` = SHAKE-256 per FIPS 203 |
| Java | SLH-DSA | All 12 parameter sets had wrong `hPrime`, `d`, `a` values | Corrected to FIPS 205 Table 1 |
| Java | SLH-DSA | `(1L << 64) - 1 == 0` overflow for treeBits=64 | Skip mask when `treeBits == 64` |

## Documentation

See **[MANUAL.md](MANUAL.md)** for:
- Quick start examples in all 8 languages
- Complete API reference for every algorithm and language
- Parameter set selection guide
- Security considerations and best practices
- Migration guide from RSA/ECDH/ECDSA
- Building, testing, and integration instructions
- Performance benchmarks
- FAQ

## Security

- Constant-time operations (no secret-dependent branches or memory accesses in crypto paths)
- Implicit rejection on decapsulation failure (ML-KEM)
- OS CSPRNG for all randomness (`SecureRandom`, `crypto/rand`, `OsRng`, etc.)
- No unsafe code in crypto paths (Rust, Go)
- All implementations verified against NIST FIPS 203/204/205 test vectors

## License

MIT — see [LICENSE](LICENSE)
