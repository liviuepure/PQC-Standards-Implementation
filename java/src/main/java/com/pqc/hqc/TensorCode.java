package com.pqc.hqc;

/**
 * Tensor product code: concatenated RS (outer) x RM (inner) code.
 * <p>
 * Encoding: message m (k bytes) -> RS encode to n1 bytes -> each byte RM-encoded
 * to n2 bits -> total n1*n2 bits.
 * <p>
 * Decoding: received n1*n2 bits -> split into n1 blocks of n2 bits each ->
 * RM-decode each block to get n1 bytes -> RS-decode to get k bytes.
 */
final class TensorCode {

    private TensorCode() {}

    /** Encodes a k-byte message into an n1*n2-bit codeword. */
    static long[] encode(byte[] msg, HqcParams p) {
        // Step 1: RS encode the message
        int[] msgInts = new int[p.k];
        for (int i = 0; i < p.k; i++) {
            msgInts[i] = msg[i] & 0xFF;
        }
        int[] rsCodeword = ReedSolomon.encode(msgInts, p);

        // Step 2: RM encode each RS symbol
        long[] out = new long[p.vecN1N2Size64];
        for (int i = 0; i < p.n1; i++) {
            ReedMuller.encodeInto(out, rsCodeword[i], i * p.n2, p.multiplicity);
        }

        return out;
    }

    /**
     * Decodes a received n1*n2-bit word back to a k-byte message.
     * Returns the message or null if decoding fails.
     */
    static byte[] decode(long[] received, HqcParams p) {
        // Step 1: RM-decode each block of n2 bits to get one byte
        int[] rsReceived = new int[p.n1];
        for (int i = 0; i < p.n1; i++) {
            long[] block = extractBits(received, i * p.n2, p.n2);
            rsReceived[i] = ReedMuller.decode(block, p.n2, p.multiplicity);
        }

        // Step 2: RS-decode the n1-byte received word to get k bytes
        int[] decoded = ReedSolomon.decode(rsReceived, p);
        if (decoded == null) return null;

        byte[] msg = new byte[p.k];
        for (int i = 0; i < p.k; i++) {
            msg[i] = (byte) decoded[i];
        }
        return msg;
    }

    /**
     * Extracts nBits bits from src starting at bitOffset,
     * returning them as a long[] vector.
     */
    static long[] extractBits(long[] src, int bitOffset, int nBits) {
        int nWords = (nBits + 63) / 64;
        long[] out = new long[nWords];

        int srcWord = bitOffset / 64;
        int srcBit = bitOffset % 64;

        if (srcBit == 0) {
            for (int i = 0; i < nWords && srcWord + i < src.length; i++) {
                out[i] = src[srcWord + i];
            }
        } else {
            for (int i = 0; i < nWords; i++) {
                int idx = srcWord + i;
                if (idx < src.length) {
                    out[i] = src[idx] >>> srcBit;
                }
                if (idx + 1 < src.length) {
                    out[i] |= src[idx + 1] << (64 - srcBit);
                }
            }
        }

        int rem = nBits % 64;
        if (rem != 0 && nWords > 0) {
            out[nWords - 1] &= (1L << rem) - 1;
        }

        return out;
    }
}
