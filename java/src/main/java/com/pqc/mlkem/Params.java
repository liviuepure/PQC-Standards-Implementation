package com.pqc.mlkem;

/**
 * ML-KEM parameter sets (FIPS 203 Table 2).
 */
public final class Params {

    public final String name;
    public final int k;
    public final int eta1;
    public final int eta2;
    public final int du;
    public final int dv;
    public final int ekSize;
    public final int dkSize;
    public final int ctSize;

    public Params(String name, int k, int eta1, int eta2, int du, int dv) {
        this.name = name;
        this.k = k;
        this.eta1 = eta1;
        this.eta2 = eta2;
        this.du = du;
        this.dv = dv;
        // ekSize = 384*k + 32
        this.ekSize = 384 * k + 32;
        // dkSize = 768*k + 96
        this.dkSize = 768 * k + 96;
        // ctSize = 32*(du*k + dv)
        this.ctSize = 32 * (du * k + dv);
    }

    public static final Params ML_KEM_512 = new Params("ML-KEM-512", 2, 3, 2, 10, 4);
    public static final Params ML_KEM_768 = new Params("ML-KEM-768", 3, 2, 2, 10, 4);
    public static final Params ML_KEM_1024 = new Params("ML-KEM-1024", 4, 2, 2, 11, 5);
}
