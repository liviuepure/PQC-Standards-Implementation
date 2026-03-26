package com.pqc.mlkem;

import java.util.Arrays;

import static com.pqc.mlkem.Field.*;

/**
 * K-PKE: the underlying public-key encryption scheme for ML-KEM.
 * FIPS 203 Algorithms 13, 14, 15.
 */
public final class KPKE {

    private KPKE() {}

    public record KeyPair(byte[] ekPKE, byte[] dkPKE) {}

    /**
     * Algorithm 13: K-PKE.KeyGen.
     * Input: d (32 bytes of randomness).
     * Output: encryption key ekPKE and decryption key dkPKE.
     */
    public static KeyPair keyGen(byte[] d, Params params) {
        int k = params.k;

        byte[][] gResult = HashFuncs.G(concat(d, new byte[]{(byte) k}));
        byte[] rho = gResult[0];
        byte[] sigma = gResult[1];

        // Generate matrix A_hat (in NTT domain) - k x k
        int[][] AHat = new int[k * k][];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                byte[] xofBytes = HashFuncs.xof(rho, j, i);
                AHat[i * k + j] = Sampling.sampleNTT(xofBytes);
            }
        }

        // Generate secret vector s (in NTT domain)
        int[][] sHat = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] prfBytes = HashFuncs.prf(sigma, i, 64 * params.eta1);
            sHat[i] = NTT.ntt(Sampling.samplePolyCBD(prfBytes, params.eta1));
        }

        // Generate error vector e (in NTT domain)
        int[][] eHat = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] prfBytes = HashFuncs.prf(sigma, k + i, 64 * params.eta1);
            eHat[i] = NTT.ntt(Sampling.samplePolyCBD(prfBytes, params.eta1));
        }

        // Compute t_hat = A_hat * s_hat + e_hat
        int[][] tHat = new int[k][];
        for (int i = 0; i < k; i++) {
            tHat[i] = new int[256];
            for (int j = 0; j < k; j++) {
                int[] prod = NTT.multiplyNTTs(AHat[i * k + j], sHat[j]);
                for (int c = 0; c < 256; c++) {
                    tHat[i][c] = fieldAdd(tHat[i][c], prod[c]);
                }
            }
            for (int c = 0; c < 256; c++) {
                tHat[i][c] = fieldAdd(tHat[i][c], eHat[i][c]);
            }
        }

        // Encode ekPKE = ByteEncode_12(t_hat[0]) || ... || ByteEncode_12(t_hat[k-1]) || rho
        byte[] ekPKE = new byte[384 * k + 32];
        for (int i = 0; i < k; i++) {
            byte[] enc = Encode.byteEncode(12, tHat[i]);
            System.arraycopy(enc, 0, ekPKE, 384 * i, 384);
        }
        System.arraycopy(rho, 0, ekPKE, 384 * k, 32);

        // Encode dkPKE = ByteEncode_12(s_hat[0]) || ... || ByteEncode_12(s_hat[k-1])
        byte[] dkPKE = new byte[384 * k];
        for (int i = 0; i < k; i++) {
            byte[] enc = Encode.byteEncode(12, sHat[i]);
            System.arraycopy(enc, 0, dkPKE, 384 * i, 384);
        }

        return new KeyPair(ekPKE, dkPKE);
    }

    /**
     * Algorithm 14: K-PKE.Encrypt.
     */
    public static byte[] encrypt(byte[] ekPKE, byte[] m, byte[] r, Params params) {
        int k = params.k;

        // Decode t_hat from ekPKE
        int[][] tHat = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] slice = Arrays.copyOfRange(ekPKE, 384 * i, 384 * (i + 1));
            tHat[i] = Encode.byteDecode(12, slice);
            // Reduce mod Q for decoded d=12
            for (int c = 0; c < 256; c++) {
                tHat[i][c] = mod(tHat[i][c], Q);
            }
        }
        byte[] rho = Arrays.copyOfRange(ekPKE, 384 * k, 384 * k + 32);

        // Regenerate matrix A_hat
        int[][] AHat = new int[k * k][];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                byte[] xofBytes = HashFuncs.xof(rho, j, i);
                AHat[i * k + j] = Sampling.sampleNTT(xofBytes);
            }
        }

        // Generate r vector
        int[][] rVec = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] prfBytes = HashFuncs.prf(r, i, 64 * params.eta1);
            rVec[i] = NTT.ntt(Sampling.samplePolyCBD(prfBytes, params.eta1));
        }

        // Generate e1 vector
        int[][] e1 = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] prfBytes = HashFuncs.prf(r, k + i, 64 * params.eta2);
            e1[i] = Sampling.samplePolyCBD(prfBytes, params.eta2);
        }

        // Generate e2 scalar
        byte[] prfBytes = HashFuncs.prf(r, 2 * k, 64 * params.eta2);
        int[] e2 = Sampling.samplePolyCBD(prfBytes, params.eta2);

        // Compute u = NTT^{-1}(A_hat^T * r_hat) + e1
        int[][] u = new int[k][];
        for (int i = 0; i < k; i++) {
            int[] sum = new int[256];
            for (int j = 0; j < k; j++) {
                // A_hat^T[i][j] = AHat[j][i] (transpose)
                int[] prod = NTT.multiplyNTTs(AHat[j * k + i], rVec[j]);
                for (int c = 0; c < 256; c++) {
                    sum[c] = fieldAdd(sum[c], prod[c]);
                }
            }
            u[i] = NTT.nttInverse(sum);
            for (int c = 0; c < 256; c++) {
                u[i][c] = fieldAdd(u[i][c], e1[i][c]);
            }
        }

        // Decode message polynomial
        int[] mu = Compress.decompressPoly(1, Encode.byteDecode(1, m));

        // Compute v = NTT^{-1}(t_hat^T * r_hat) + e2 + mu
        int[] vSum = new int[256];
        for (int j = 0; j < k; j++) {
            int[] prod = NTT.multiplyNTTs(tHat[j], rVec[j]);
            for (int c = 0; c < 256; c++) {
                vSum[c] = fieldAdd(vSum[c], prod[c]);
            }
        }
        int[] v = NTT.nttInverse(vSum);
        for (int c = 0; c < 256; c++) {
            v[c] = fieldAdd(fieldAdd(v[c], e2[c]), mu[c]);
        }

        // Encode ciphertext
        // c1 = ByteEncode_du(Compress_du(u[i])) for each i
        int c1Len = 32 * params.du;
        byte[] c = new byte[32 * (params.du * k + params.dv)];
        for (int i = 0; i < k; i++) {
            int[] compressed = Compress.compressPoly(params.du, u[i]);
            byte[] enc = Encode.byteEncode(params.du, compressed);
            System.arraycopy(enc, 0, c, c1Len * i, c1Len);
        }
        // c2 = ByteEncode_dv(Compress_dv(v))
        int[] compressedV = Compress.compressPoly(params.dv, v);
        byte[] encV = Encode.byteEncode(params.dv, compressedV);
        System.arraycopy(encV, 0, c, c1Len * k, encV.length);

        return c;
    }

    /**
     * Algorithm 15: K-PKE.Decrypt.
     */
    public static byte[] decrypt(byte[] dkPKE, byte[] c, Params params) {
        int k = params.k;
        int c1Len = 32 * params.du;

        // Decode u from c1
        int[][] u = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] slice = Arrays.copyOfRange(c, c1Len * i, c1Len * (i + 1));
            int[] decoded = Encode.byteDecode(params.du, slice);
            u[i] = Compress.decompressPoly(params.du, decoded);
        }

        // Decode v from c2
        byte[] c2 = Arrays.copyOfRange(c, c1Len * k, c.length);
        int[] decodedV = Encode.byteDecode(params.dv, c2);
        int[] v = Compress.decompressPoly(params.dv, decodedV);

        // Decode secret key s_hat
        int[][] sHat = new int[k][];
        for (int i = 0; i < k; i++) {
            byte[] slice = Arrays.copyOfRange(dkPKE, 384 * i, 384 * (i + 1));
            sHat[i] = Encode.byteDecode(12, slice);
            for (int co = 0; co < 256; co++) {
                sHat[i][co] = mod(sHat[i][co], Q);
            }
        }

        // Compute w = v - NTT^{-1}(s_hat^T * NTT(u))
        int[] inner = new int[256];
        for (int j = 0; j < k; j++) {
            int[] uHat = NTT.ntt(u[j]);
            int[] prod = NTT.multiplyNTTs(sHat[j], uHat);
            for (int co = 0; co < 256; co++) {
                inner[co] = fieldAdd(inner[co], prod[co]);
            }
        }
        int[] innerInv = NTT.nttInverse(inner);
        int[] w = new int[256];
        for (int co = 0; co < 256; co++) {
            w[co] = fieldSub(v[co], innerInv[co]);
        }

        // Encode message
        return Encode.byteEncode(1, Compress.compressPoly(1, w));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
