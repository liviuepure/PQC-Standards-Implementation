package com.pqc.mlkem;

/**
 * Finite field arithmetic modulo Q = 3329.
 */
public final class Field {

    public static final int Q = 3329;

    private Field() {}

    /**
     * Reduce a mod q into range [0, q).
     */
    public static int mod(int a, int q) {
        int r = a % q;
        return r < 0 ? r + q : r;
    }

    public static int fieldAdd(int a, int b) {
        return mod(a + b, Q);
    }

    public static int fieldSub(int a, int b) {
        return mod(a - b, Q);
    }

    public static int fieldMul(int a, int b) {
        return mod(a * b, Q);
    }

    /**
     * Modular exponentiation: base^exp mod Q.
     */
    public static int fieldPow(int base, int exp) {
        base = mod(base, Q);
        int result = 1;
        for (int i = 0; i < exp; i++) {
            result = fieldMul(result, base);
        }
        return result;
    }
}
