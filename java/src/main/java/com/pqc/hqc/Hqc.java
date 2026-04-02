package com.pqc.hqc;

import com.pqc.common.Keccak;

import java.security.SecureRandom;

/**
 * HQC (Hamming Quasi-Cyclic) Key Encapsulation Mechanism.
 * <p>
 * Public API providing keyGen, encaps, and decaps operations.
 * Uses SHAKE-256 (via the existing Keccak class) for hashing and seed expansion.
 */
public final class Hqc {

    private Hqc() {}

    /**
     * Generates an HQC key pair.
     *
     * @param p the HQC parameter set
     * @return array of [publicKey, secretKey]
     */
    public static byte[][] keyGen(HqcParams p) {
        return keyGen(p, new SecureRandom());
    }

    /**
     * Generates an HQC key pair with the given random source.
     *
     * @param p   the HQC parameter set
     * @param rng the random source
     * @return array of [publicKey, secretKey]
     */
    public static byte[][] keyGen(HqcParams p, SecureRandom rng) {
        byte[] skSeed = new byte[HqcParams.SEED_BYTES];
        rng.nextBytes(skSeed);
        byte[] pkSeed = new byte[HqcParams.SEED_BYTES];
        rng.nextBytes(pkSeed);

        // Generate secret vectors x, y from sk_seed
        SeedExpander skExpander = new SeedExpander(skSeed);
        long[] x = vectSetRandomFixedWeight(skExpander, p.n, p.w);
        long[] y = vectSetRandomFixedWeight(skExpander, p.n, p.w);

        // Generate random vector h from pk_seed
        SeedExpander pkExpander = new SeedExpander(pkSeed);
        long[] h = vectSetRandom(pkExpander, p.n);

        // Compute s = x + h * y mod (x^n - 1)
        long[] hy = GF2.vectMul(h, y, p.n);
        long[] s = GF2.vectAdd(hy, x);
        s = GF2.vectResize(s, p.n);

        // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
        byte[] pk = new byte[p.pkSize];
        System.arraycopy(pkSeed, 0, pk, 0, HqcParams.SEED_BYTES);
        byte[] sBytes = GF2.vectToBytes(s, p.vecNSizeBytes);
        System.arraycopy(sBytes, 0, pk, HqcParams.SEED_BYTES, sBytes.length);

        // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
        byte[] sk = new byte[p.skSize];
        System.arraycopy(skSeed, 0, sk, 0, HqcParams.SEED_BYTES);
        System.arraycopy(pk, 0, sk, HqcParams.SEED_BYTES, pk.length);

        return new byte[][]{ pk, sk };
    }

    /**
     * Encapsulates a shared secret using the public key.
     *
     * @param pk the public key
     * @param p  the HQC parameter set
     * @return array of [ciphertext, sharedSecret]
     */
    public static byte[][] encaps(byte[] pk, HqcParams p) {
        return encaps(pk, p, new SecureRandom());
    }

    /**
     * Encapsulates a shared secret using the public key with the given random source.
     *
     * @param pk  the public key
     * @param p   the HQC parameter set
     * @param rng the random source
     * @return array of [ciphertext, sharedSecret]
     */
    public static byte[][] encaps(byte[] pk, HqcParams p, SecureRandom rng) {
        // Generate random message m
        byte[] m = new byte[p.vecKSizeBytes];
        rng.nextBytes(m);

        // Compute d = H(m)
        byte[] d = computeD(m);

        // Compute theta = G(m || pk || d)
        byte[] theta = computeTheta(m, pk, d);

        // PKE Encrypt
        long[][] uv = pkeEncrypt(m, theta, pk, p);
        long[] u = uv[0];
        long[] v = uv[1];

        // Compute shared secret
        byte[] ss = computeSS(m, u, v, p);

        // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
        byte[] ct = new byte[p.ctSize];
        byte[] uBytes = GF2.vectToBytes(u, p.vecNSizeBytes);
        byte[] vBytes = GF2.vectToBytes(v, p.vecN1N2SizeBytes);
        System.arraycopy(uBytes, 0, ct, 0, uBytes.length);
        System.arraycopy(vBytes, 0, ct, p.vecNSizeBytes, vBytes.length);
        System.arraycopy(d, 0, ct, p.vecNSizeBytes + p.vecN1N2SizeBytes, d.length);

        return new byte[][]{ ct, ss };
    }

    /**
     * Decapsulates a shared secret from a ciphertext using the secret key.
     *
     * @param sk the secret key
     * @param ct the ciphertext
     * @param p  the HQC parameter set
     * @return the shared secret
     */
    public static byte[] decaps(byte[] sk, byte[] ct, HqcParams p) {
        // Parse secret key
        byte[] skSeed = new byte[HqcParams.SEED_BYTES];
        System.arraycopy(sk, 0, skSeed, 0, HqcParams.SEED_BYTES);
        byte[] pk = new byte[p.pkSize];
        System.arraycopy(sk, HqcParams.SEED_BYTES, pk, 0, p.pkSize);

        // Parse ciphertext
        long[] u = GF2.vectFromBytes(ct, p.vecNSize64);
        byte[] vBuf = new byte[p.vecN1N2SizeBytes];
        System.arraycopy(ct, p.vecNSizeBytes, vBuf, 0, p.vecN1N2SizeBytes);
        long[] v = GF2.vectFromBytes(vBuf, p.vecN1N2Size64);
        byte[] d = new byte[HqcParams.HASH_BYTES];
        System.arraycopy(ct, p.vecNSizeBytes + p.vecN1N2SizeBytes, d, 0, HqcParams.HASH_BYTES);

        // Regenerate secret vectors x, y and sigma from sk_seed
        SeedExpander skExpander = new SeedExpander(skSeed);
        vectSetRandomFixedWeight(skExpander, p.n, p.w); // x (not needed for decrypt)
        long[] y = vectSetRandomFixedWeight(skExpander, p.n, p.w);
        byte[] sigma = new byte[p.vecKSizeBytes];
        skExpander.read(sigma);

        // Compute v - u * y (XOR since GF(2))
        long[] uy = GF2.vectMul(u, y, p.n);

        long[] uyTrunc = new long[p.vecN1N2Size64];
        System.arraycopy(uy, 0, uyTrunc, 0, Math.min(uy.length, p.vecN1N2Size64));
        if (p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0) {
            uyTrunc[p.vecN1N2Size64 - 1] &= (1L << (p.n1n2 % 64)) - 1;
        }

        long[] vMinusUY = GF2.vectAdd(v, uyTrunc);

        // Decode using tensor product code
        byte[] mPrime = TensorCode.decode(vMinusUY, p);
        if (mPrime == null) {
            mPrime = new byte[p.vecKSizeBytes];
            System.arraycopy(sigma, 0, mPrime, 0, p.vecKSizeBytes);
        }

        // Re-encrypt to verify
        byte[] thetaPrime = computeTheta(mPrime, pk, d);
        long[][] uv2 = pkeEncrypt(mPrime, thetaPrime, pk, p);
        long[] u2 = uv2[0];
        long[] v2 = uv2[1];

        // Constant-time comparison
        long[] u2Trunc = GF2.vectResize(u2, p.n);
        long[] uOrig = GF2.vectResize(u, p.n);
        int uMatch = GF2.vectEqual(u2Trunc, uOrig);

        long[] v2Trunc = GF2.vectResize(v2, p.n1n2);
        long[] vOrig = GF2.vectResize(v, p.n1n2);
        int vMatch = GF2.vectEqual(v2Trunc, vOrig);

        int match = uMatch & vMatch;

        // Constant-time selection of message or sigma
        byte[] mc = new byte[p.vecKSizeBytes];
        byte maskOK = (byte) (0 - match);          // 0xFF if match, 0x00 otherwise
        byte maskFail = (byte) (0 - (1 - match));  // 0x00 if match, 0xFF otherwise
        for (int i = 0; i < p.vecKSizeBytes; i++) {
            mc[i] = (byte) ((mPrime[i] & maskOK) | (sigma[i] & maskFail));
        }

        return computeSS(mc, u, v, p);
    }

    // --- PKE Encrypt ---

    private static long[][] pkeEncrypt(byte[] m, byte[] theta, byte[] pk, HqcParams p) {
        byte[] pkSeed = new byte[HqcParams.SEED_BYTES];
        System.arraycopy(pk, 0, pkSeed, 0, HqcParams.SEED_BYTES);
        byte[] sBuf = new byte[pk.length - HqcParams.SEED_BYTES];
        System.arraycopy(pk, HqcParams.SEED_BYTES, sBuf, 0, sBuf.length);
        long[] s = GF2.vectFromBytes(sBuf, p.vecNSize64);

        // Generate h from pk_seed
        SeedExpander pkExpander = new SeedExpander(pkSeed);
        long[] h = vectSetRandom(pkExpander, p.n);

        // Generate r1, r2 with weight WR and e with weight WE from theta
        SeedExpander thetaExpander = new SeedExpander(theta);
        long[] r1 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr);
        long[] r2 = vectSetRandomFixedWeight(thetaExpander, p.n, p.wr);
        long[] e = vectSetRandomFixedWeight(thetaExpander, p.n, p.we);

        // u = r1 + h * r2 mod (x^n - 1)
        long[] hr2 = GF2.vectMul(h, r2, p.n);
        long[] u = GF2.vectAdd(hr2, r1);
        u = GF2.vectResize(u, p.n);

        // v = encode(m) + s * r2 + e
        long[] encoded = TensorCode.encode(m, p);

        long[] sr2 = GF2.vectMul(s, r2, p.n);
        long[] sr2Trunc = new long[p.vecN1N2Size64];
        System.arraycopy(sr2, 0, sr2Trunc, 0, Math.min(sr2.length, p.vecN1N2Size64));
        if (p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0) {
            sr2Trunc[p.vecN1N2Size64 - 1] &= (1L << (p.n1n2 % 64)) - 1;
        }

        long[] eResized = new long[p.vecN1N2Size64];
        System.arraycopy(e, 0, eResized, 0, Math.min(e.length, p.vecN1N2Size64));
        if (p.n1n2 % 64 != 0 && p.vecN1N2Size64 > 0) {
            eResized[p.vecN1N2Size64 - 1] &= (1L << (p.n1n2 % 64)) - 1;
        }

        long[] v = GF2.vectAdd(encoded, sr2Trunc);
        v = GF2.vectAdd(v, eResized);
        v = GF2.vectResize(v, p.n1n2);

        return new long[][]{ u, v };
    }

    // --- Hash functions ---

    /** d = SHAKE256(H_domain || m), 64 bytes. */
    private static byte[] computeD(byte[] m) {
        byte[] input = new byte[1 + m.length];
        input[0] = HqcParams.H_FCT_DOMAIN;
        System.arraycopy(m, 0, input, 1, m.length);
        return Keccak.shake256(input, HqcParams.SHARED_SECRET_BYTES);
    }

    /** theta = SHAKE256(G_domain || m || pk || d), SEED_BYTES output. */
    private static byte[] computeTheta(byte[] m, byte[] pk, byte[] d) {
        byte[] input = new byte[1 + m.length + pk.length + d.length];
        input[0] = HqcParams.G_FCT_DOMAIN;
        int off = 1;
        System.arraycopy(m, 0, input, off, m.length);
        off += m.length;
        System.arraycopy(pk, 0, input, off, pk.length);
        off += pk.length;
        System.arraycopy(d, 0, input, off, d.length);
        return Keccak.shake256(input, HqcParams.SEED_BYTES);
    }

    /** ss = SHAKE256(K_domain || m || u_bytes || v_bytes), 64 bytes. */
    private static byte[] computeSS(byte[] m, long[] u, long[] v, HqcParams p) {
        byte[] uBytes = GF2.vectToBytes(u, p.vecNSizeBytes);
        byte[] vBytes = GF2.vectToBytes(v, p.vecN1N2SizeBytes);
        byte[] input = new byte[1 + m.length + uBytes.length + vBytes.length];
        input[0] = HqcParams.K_FCT_DOMAIN;
        int off = 1;
        System.arraycopy(m, 0, input, off, m.length);
        off += m.length;
        System.arraycopy(uBytes, 0, input, off, uBytes.length);
        off += uBytes.length;
        System.arraycopy(vBytes, 0, input, off, vBytes.length);
        return Keccak.shake256(input, HqcParams.SHARED_SECRET_BYTES);
    }

    // --- Seed Expander (SHAKE-256 based) ---

    /**
     * SHAKE-256 based seed expander for deterministic random generation.
     * Uses Keccak absorb/squeeze for streaming output.
     */
    static final class SeedExpander {
        private final long[] state;
        private static final int RATE_BYTES = 136;
        private final byte[] buffer;
        private int bufPos;

        SeedExpander(byte[] seed) {
            state = Keccak.keccakAbsorb(seed, RATE_BYTES, (byte) 0x1F);
            buffer = new byte[RATE_BYTES];
            // Fill initial buffer
            fillBuffer();
        }

        private void fillBuffer() {
            int rateLongs = RATE_BYTES / 8;
            for (int i = 0; i < rateLongs; i++) {
                long val = state[i];
                int off = i * 8;
                buffer[off]     = (byte) val;
                buffer[off + 1] = (byte) (val >>> 8);
                buffer[off + 2] = (byte) (val >>> 16);
                buffer[off + 3] = (byte) (val >>> 24);
                buffer[off + 4] = (byte) (val >>> 32);
                buffer[off + 5] = (byte) (val >>> 40);
                buffer[off + 6] = (byte) (val >>> 48);
                buffer[off + 7] = (byte) (val >>> 56);
            }
            bufPos = 0;
        }

        void read(byte[] out) {
            read(out, 0, out.length);
        }

        void read(byte[] out, int offset, int len) {
            int remaining = len;
            int pos = offset;
            while (remaining > 0) {
                int available = RATE_BYTES - bufPos;
                if (available <= 0) {
                    Keccak.keccakF1600(state);
                    fillBuffer();
                    available = RATE_BYTES;
                }
                int toCopy = Math.min(remaining, available);
                System.arraycopy(buffer, bufPos, out, pos, toCopy);
                bufPos += toCopy;
                pos += toCopy;
                remaining -= toCopy;
            }
        }
    }

    // --- Random vector generation ---

    /** Generates a random vector of n bits using the seed expander. */
    private static long[] vectSetRandom(SeedExpander se, int n) {
        int nWords = (n + 63) / 64;
        int nBytes = nWords * 8;
        byte[] buf = new byte[nBytes];
        se.read(buf);
        long[] v = GF2.vectFromBytes(buf, nWords);
        int rem = n % 64;
        if (rem != 0) {
            v[nWords - 1] &= (1L << rem) - 1;
        }
        return v;
    }

    /**
     * Generates a random vector of n bits with exactly 'weight' bits set,
     * using the seed expander. Uses rejection sampling for duplicate positions.
     */
    private static long[] vectSetRandomFixedWeight(SeedExpander se, int n, int weight) {
        int nWords = (n + 63) / 64;
        long[] v = new long[nWords];

        int[] positions = new int[weight];
        byte[] buf = new byte[4];

        for (int i = 0; i < weight; i++) {
            outer:
            while (true) {
                se.read(buf);
                long pos = ((buf[0] & 0xFFL)
                         | ((buf[1] & 0xFFL) << 8)
                         | ((buf[2] & 0xFFL) << 16)
                         | ((buf[3] & 0xFFL) << 24));
                pos = Long.remainderUnsigned(pos, n);

                for (int j = 0; j < i; j++) {
                    if (positions[j] == (int) pos) {
                        continue outer;
                    }
                }
                positions[i] = (int) pos;
                break;
            }
        }

        for (int pos : positions) {
            GF2.vectSetBit(v, pos);
        }

        return v;
    }
}
