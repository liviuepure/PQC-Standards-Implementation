package com.pqc.fndsa;

/**
 * FN-DSA parameter sets (FIPS 206 / FALCON).
 * q = 12289, ring Z[x]/(x^n+1), n in {512, 1024}.
 */
public final class Params {

    public static final int Q = 12289;

    public final String name;
    public final int n;
    public final int logN;
    public final boolean padded;
    public final int pkSize;
    public final int skSize;
    /** For padded variants: fixed sig size. For non-padded: max variable sig size. */
    public final int sigSize;
    /** Always the max variable-length sig size before padding. */
    public final int sigMaxLen;
    public final long betaSq;
    public final int fgBits;

    public Params(String name, int n, int logN, boolean padded,
                  int pkSize, int skSize, int sigSize, int sigMaxLen,
                  long betaSq, int fgBits) {
        this.name = name;
        this.n = n;
        this.logN = logN;
        this.padded = padded;
        this.pkSize = pkSize;
        this.skSize = skSize;
        this.sigSize = sigSize;
        this.sigMaxLen = sigMaxLen;
        this.betaSq = betaSq;
        this.fgBits = fgBits;
    }

    public static final Params FNDSA512 = new Params(
        "FN-DSA-512", 512, 9, false, 897, 1281, 666, 666, 34034726L, 6);

    public static final Params FNDSA1024 = new Params(
        "FN-DSA-1024", 1024, 10, false, 1793, 2305, 1280, 1280, 70265242L, 5);

    public static final Params FNDSA_PADDED_512 = new Params(
        "FN-DSA-PADDED-512", 512, 9, true, 897, 1281, 809, 666, 34034726L, 6);

    public static final Params FNDSA_PADDED_1024 = new Params(
        "FN-DSA-PADDED-1024", 1024, 10, true, 1793, 2305, 1473, 1280, 70265242L, 5);

    @Override
    public String toString() {
        return name;
    }
}
