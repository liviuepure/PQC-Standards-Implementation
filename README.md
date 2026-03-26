# PQC Standards Implementation

Pure implementations of NIST Post-Quantum Cryptography standards across multiple programming languages.

## Standards

| Standard | Algorithm | Type | Status |
|----------|-----------|------|--------|
| **FIPS 203** | ML-KEM (Kyber) | Key Encapsulation | ✅ All languages |
| **FIPS 204** | ML-DSA (Dilithium) | Digital Signature | Planned |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-Based Signature | Planned |
| Hybrid KEMs | X25519MLKEM768, X-Wing | Hybrid Key Exchange | Planned |
| Composite Sigs | ML-DSA + Ed25519/ECDSA | Hybrid Signatures | Planned |
| TLS 1.3 | Integration layer | Protocol Integration | Planned |

## Languages

| Language | ML-KEM | ML-DSA | SLH-DSA | Hybrid | TLS |
|----------|--------|--------|---------|--------|-----|
| Rust     | ✅     | -      | -       | -      | -   |
| Go       | ✅     | -      | -       | -      | -   |
| JS/TS    | ✅     | -      | -       | -      | -   |
| Python   | ✅     | -      | -       | -      | -   |
| Java     | ✅     | -      | -       | -      | -   |

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
│   └── ml-kem/     # ML-KEM (FIPS 203)
├── go/             # Go implementations
├── js/             # JavaScript (ES modules, Node.js 20+)
├── python/         # Python implementations (3.10+)
├── java/           # Java implementations (17+, Maven)
└── test-vectors/   # Shared NIST KAT vectors
```

## Security

- Constant-time operations (no secret-dependent branches)
- Implicit rejection on decapsulation failure
- No unsafe code in crypto paths
- OS CSPRNG for all randomness

## License

MIT — see [LICENSE](LICENSE)
