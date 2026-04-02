package com.pqc.hqc;

/**
 * Parameter sets for HQC (Hamming Quasi-Cyclic) KEM.
 * <p>
 * HQC is a code-based key encapsulation mechanism selected by NIST for
 * post-quantum cryptography standardization. Each parameter set targets
 * a different NIST security level.
 */
public final class HqcParams {

    /** Parameter set name. */
    public final String name;
    /** Ring dimension (polynomial degree mod x^n - 1). */
    public final int n;
    /** Reed-Solomon codeword length. */
    public final int n1;
    /** Reed-Muller codeword length (duplicated). */
    public final int n2;
    /** Concatenated code length in bits = n1 * n2. */
    public final int n1n2;
    /** Message size in bytes (RS information symbols). */
    public final int k;
    /** RS error correction capability. */
    public final int delta;
    /** RS generator polynomial degree = 2*delta + 1. */
    public final int g;
    /** Weight of secret key vectors x, y. */
    public final int w;
    /** Weight of encryption vectors r1, r2. */
    public final int wr;
    /** Weight of ephemeral error vector e. */
    public final int we;
    /** Public key size in bytes. */
    public final int pkSize;
    /** Secret key size in bytes. */
    public final int skSize;
    /** Ciphertext size in bytes. */
    public final int ctSize;
    /** Shared secret size in bytes. */
    public final int ssSize;

    // Derived sizes
    /** ceil(n / 64). */
    public final int vecNSize64;
    /** ceil(n / 8). */
    public final int vecNSizeBytes;
    /** ceil(n1n2 / 64). */
    public final int vecN1N2Size64;
    /** ceil(n1n2 / 8). */
    public final int vecN1N2SizeBytes;
    /** k bytes. */
    public final int vecKSizeBytes;

    /** GF(2^8) irreducible polynomial. */
    public final int gfPoly;
    /** GF(2^8) multiplicative order = 255. */
    public final int gfMulOrder;

    /** RM(1, rmOrder), base codeword length = 2^rmOrder = 128. */
    public final int rmOrder;
    /** Number of repetitions: n2 / 128. */
    public final int multiplicity;

    // Constants
    /** Seed size used for key generation. */
    public static final int SEED_BYTES = 40;
    /** Size of d = H(m) included in the ciphertext (SHAKE256 output). */
    public static final int HASH_BYTES = 64;
    /** Shared secret size (SHAKE256-512 output). */
    public static final int SHARED_SECRET_BYTES = 64;

    /** Domain separation byte for theta = G(m || pk || salt). */
    public static final byte G_FCT_DOMAIN = 3;
    /** Domain separation byte for d = H(m). */
    public static final byte H_FCT_DOMAIN = 4;
    /** Domain separation byte for ss = K(m || ct). */
    public static final byte K_FCT_DOMAIN = 5;

    private HqcParams(String name, int n, int n1, int n2, int k, int delta,
                      int w, int wr, int we,
                      int pkSize, int skSize, int ctSize,
                      int multiplicity) {
        this.name = name;
        this.n = n;
        this.n1 = n1;
        this.n2 = n2;
        this.n1n2 = n1 * n2;
        this.k = k;
        this.delta = delta;
        this.g = 2 * delta + 1;
        this.w = w;
        this.wr = wr;
        this.we = we;
        this.pkSize = pkSize;
        this.skSize = skSize;
        this.ctSize = ctSize;
        this.ssSize = SHARED_SECRET_BYTES;

        this.vecNSize64 = (n + 63) / 64;
        this.vecNSizeBytes = (n + 7) / 8;
        this.vecN1N2Size64 = (this.n1n2 + 63) / 64;
        this.vecN1N2SizeBytes = (this.n1n2 + 7) / 8;
        this.vecKSizeBytes = k;

        this.gfPoly = 0x11D;
        this.gfMulOrder = 255;
        this.rmOrder = 7;
        this.multiplicity = multiplicity;
    }

    /** HQC-128 targets NIST security level 1 (128-bit). */
    public static final HqcParams HQC_128 = new HqcParams(
        "HQC-128", 17669, 46, 384, 16, 15, 66, 77, 77,
        2249, 2289, 4481, 3
    );

    /** HQC-192 targets NIST security level 3 (192-bit). */
    public static final HqcParams HQC_192 = new HqcParams(
        "HQC-192", 35851, 56, 640, 24, 16, 100, 117, 117,
        4522, 4562, 9026, 5
    );

    /** HQC-256 targets NIST security level 5 (256-bit). */
    public static final HqcParams HQC_256 = new HqcParams(
        "HQC-256", 57637, 90, 640, 32, 29, 131, 153, 153,
        7245, 7285, 14469, 5
    );

    /** Returns all supported HQC parameter sets. */
    public static HqcParams[] allParams() {
        return new HqcParams[]{ HQC_128, HQC_192, HQC_256 };
    }

    @Override
    public String toString() {
        return name;
    }
}
