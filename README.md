# PQC Standards Implementation

Pure implementations of NIST Post-Quantum Cryptography standards across multiple programming languages.

## Standards

| Standard | Algorithm | Type | Status |
|----------|-----------|------|--------|
| **FIPS 203** | ML-KEM (Kyber) | Key Encapsulation | ✅ All languages |
| **FIPS 204** | ML-DSA (Dilithium) | Digital Signature | ✅ All languages |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-Based Signature | ✅ All languages |
| Hybrid KEMs | X25519+ML-KEM-768, ECDH+ML-KEM | Hybrid Key Exchange | ✅ All languages |
| Composite Sigs | ML-DSA + Ed25519/ECDSA | Hybrid Signatures | ✅ All languages |
| TLS 1.3 | PQC Named Groups + Cipher Suites | Protocol Integration | ✅ All languages |

## Languages

| Language | ML-KEM | ML-DSA | SLH-DSA | Hybrid | TLS |
|----------|--------|--------|---------|--------|-----|
| Rust     | ✅     | ✅     | ✅      | ✅     | ✅  |
| Go       | ✅     | ✅     | ✅      | ✅     | ✅  |
| JS/TS    | ✅     | ✅     | ✅      | ✅     | ✅  |
| Python   | ✅     | ✅     | ✅      | ✅     | ✅  |
| Java     | ✅     | ✅     | ✅      | ✅     | ✅  |
| C#/.NET  | ✅     | ✅     | ✅      | ✅     | ✅  |
| Swift    | ✅     | ✅     | ✅      | ✅     | ✅  |
| PHP      | ✅     | ✅     | ✅      | ✅     | ✅  |

## ML-KEM — Complete (All Languages)

All parameter sets validated against official C2SP/CCTV test vectors.

```rust
use ml_kem::{MlKem768, keygen, encapsulate, decapsulate};
use rand::rngs::OsRng;

let (ek, dk) = keygen::<MlKem768>(&mut OsRng);
let (ss, ct) = encapsulate::<MlKem768>(&ek, &mut OsRng);
let recovered = decapsulate::<MlKem768>(&dk, &ct);
assert_eq!(ss, recovered);
```

### Performance (Apple M-series, no SIMD)

| Op | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|----|-----------|-----------|------------|
| KeyGen | 50 us | 76 us | 108 us |
| Encaps | 39 us | 57 us | 83 us |
| Decaps | 37 us | 55 us | 79 us |

## Repository Structure

```
PQC-Standards-Implementation/
├── rust/           # Rust implementations
│   ├── pqc-common/ # Shared field arithmetic
│   ├── ml-kem/     # ML-KEM (FIPS 203)
│   ├── ml-dsa/     # ML-DSA (FIPS 204)
│   ├── slh-dsa/    # SLH-DSA (FIPS 205)
│   ├── hybrid-kem/ # Hybrid KEMs
│   ├── composite-sig/ # Composite Signatures
│   └── pqc-tls/    # TLS 1.3 Integration
├── go/             # Go implementations
├── js/             # JavaScript (ES modules, Node.js 20+)
├── python/         # Python implementations (3.10+)
├── java/           # Java implementations (17+, Maven)
├── dotnet/         # C#/.NET implementations (10+)
├── swift/          # Swift implementations (5.9+, CryptoKit)
├── php/            # PHP implementations (8.1+)
└── test-vectors/   # Shared NIST KAT vectors
```

## Documentation

See the **[Implementation Manual](MANUAL.md)** for:
- Quick start examples in all 8 languages
- Complete API reference for every component
- Parameter set selection guide
- Security considerations and best practices
- Migration guide from RSA/ECDH/ECDSA
- Building, testing, and integration instructions
- Performance benchmarks
- FAQ

## Security

- Constant-time operations (no secret-dependent branches)
- Implicit rejection on decapsulation failure
- No unsafe code in crypto paths
- OS CSPRNG for all randomness

## License

MIT — see [LICENSE](LICENSE)
