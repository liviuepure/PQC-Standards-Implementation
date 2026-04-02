using System.Security.Cryptography;

namespace FnDsa.Hqc;

/// <summary>
/// HQC (Hamming Quasi-Cyclic) Key Encapsulation Mechanism.
/// Provides KeyGen, Encaps, and Decaps operations for CCA-secure KEM.
/// Uses SHAKE-256 (via Shake256Impl) for hashing and seed expansion.
/// </summary>
public static class HqcKem
{
    /// <summary>
    /// Generates an HQC key pair.
    /// </summary>
    /// <returns>(publicKey, secretKey)</returns>
    public static (byte[] pk, byte[] sk) KeyGen(HqcParams p)
    {
        // Generate random seeds
        byte[] skSeed = RandomNumberGenerator.GetBytes(HqcParams.SeedBytes);
        byte[] pkSeed = RandomNumberGenerator.GetBytes(HqcParams.SeedBytes);

        // Generate secret vectors x, y from sk_seed
        var skExpander = new SeedExpander(skSeed);
        ulong[] x = VectSetRandomFixedWeight(skExpander, p.N, p.W);
        ulong[] y = VectSetRandomFixedWeight(skExpander, p.N, p.W);

        // Generate random vector h from pk_seed
        var pkExpander = new SeedExpander(pkSeed);
        ulong[] h = VectSetRandom(pkExpander, p.N);

        // Compute s = x + h * y mod (x^n - 1)
        ulong[] hy = GF2.VectMul(h, y, p.N);
        ulong[] s = GF2.VectAdd(hy, x);
        s = GF2.VectResize(s, p.N);

        // Serialize public key: [pk_seed (40 bytes)] [s (VecNSizeBytes bytes)]
        byte[] pk = new byte[p.PKSize];
        Array.Copy(pkSeed, pk, HqcParams.SeedBytes);
        byte[] sBytes = GF2.VectToBytes(s, p.VecNSizeBytes);
        Array.Copy(sBytes, 0, pk, HqcParams.SeedBytes, sBytes.Length);

        // Serialize secret key: [sk_seed (40 bytes)] [pk (PKSize bytes)]
        byte[] sk = new byte[p.SKSize];
        Array.Copy(skSeed, sk, HqcParams.SeedBytes);
        Array.Copy(pk, 0, sk, HqcParams.SeedBytes, pk.Length);

        return (pk, sk);
    }

    /// <summary>
    /// Encapsulates a shared secret using the public key.
    /// </summary>
    /// <returns>(ciphertext, sharedSecret)</returns>
    public static (byte[] ct, byte[] ss) Encaps(byte[] pk, HqcParams p)
    {
        // Generate random message m
        byte[] m = RandomNumberGenerator.GetBytes(p.VecKSizeBytes);

        // Compute d = H(m)
        byte[] d = ComputeD(m);

        // Compute theta
        byte[] theta = ComputeTheta(m, pk, d, p);

        // PKE Encrypt
        var (u, v) = PkeEncrypt(m, theta, pk, p);

        // Compute shared secret
        byte[] ss = ComputeSS(m, u, v, p);

        // Serialize ciphertext: [u (VecNSizeBytes)] [v (VecN1N2SizeBytes)] [d (64 bytes)]
        byte[] ct = new byte[p.CTSize];
        byte[] uBytes = GF2.VectToBytes(u, p.VecNSizeBytes);
        byte[] vBytes = GF2.VectToBytes(v, p.VecN1N2SizeBytes);
        Array.Copy(uBytes, ct, uBytes.Length);
        Array.Copy(vBytes, 0, ct, p.VecNSizeBytes, vBytes.Length);
        Array.Copy(d, 0, ct, p.VecNSizeBytes + p.VecN1N2SizeBytes, d.Length);

        return (ct, ss);
    }

    /// <summary>
    /// Decapsulates a shared secret from a ciphertext using the secret key.
    /// </summary>
    public static byte[] Decaps(byte[] sk, byte[] ct, HqcParams p)
    {
        // Parse secret key
        byte[] skSeed = sk[..HqcParams.SeedBytes];
        byte[] pk = sk[HqcParams.SeedBytes..];

        // Parse ciphertext
        ulong[] u = GF2.VectFromBytes(ct.AsSpan(0, p.VecNSizeBytes), p.VecNSize64);
        ulong[] v = GF2.VectFromBytes(ct.AsSpan(p.VecNSizeBytes, p.VecN1N2SizeBytes), p.VecN1N2Size64);
        byte[] d = ct[(p.VecNSizeBytes + p.VecN1N2SizeBytes)..];

        // Regenerate secret vectors x, y and sigma from sk_seed
        var skExpander = new SeedExpander(skSeed);
        _ = VectSetRandomFixedWeight(skExpander, p.N, p.W); // x (not needed for decrypt)
        ulong[] y = VectSetRandomFixedWeight(skExpander, p.N, p.W);
        // Generate sigma (rejection secret)
        byte[] sigma = new byte[p.VecKSizeBytes];
        skExpander.Read(sigma);

        // Compute v - u * y (XOR in GF(2))
        ulong[] uy = GF2.VectMul(u, y, p.N);

        // Truncate uy to n1*n2 bits
        var uyTrunc = new ulong[p.VecN1N2Size64];
        Array.Copy(uy, uyTrunc, Math.Min(uy.Length, p.VecN1N2Size64));
        if (p.N1N2 % 64 != 0 && p.VecN1N2Size64 > 0)
            uyTrunc[p.VecN1N2Size64 - 1] &= (1UL << (p.N1N2 % 64)) - 1;

        ulong[] vMinusUY = GF2.VectAdd(v, uyTrunc);

        // Decode using tensor product code
        var (mPrime, ok) = TensorCode.Decode(vMinusUY, p);
        if (!ok || mPrime == null)
        {
            mPrime = new byte[p.VecKSizeBytes];
            Array.Copy(sigma, mPrime, p.VecKSizeBytes);
        }

        // Re-encrypt to verify
        byte[] thetaPrime = ComputeTheta(mPrime, pk, d, p);
        var (u2, v2) = PkeEncrypt(mPrime, thetaPrime, pk, p);

        // Constant-time comparison
        ulong[] u2Trunc = GF2.VectResize(u2, p.N);
        ulong[] uOrig = GF2.VectResize(u, p.N);
        int uMatch = GF2.VectEqual(u2Trunc, uOrig);

        ulong[] v2Trunc = GF2.VectResize(v2, p.N1N2);
        ulong[] vOrig = GF2.VectResize(v, p.N1N2);
        int vMatch = GF2.VectEqual(v2Trunc, vOrig);

        int match = uMatch & vMatch;

        // Constant-time selection of message or sigma
        byte[] mc = new byte[p.VecKSizeBytes];
        byte maskOK = (byte)(0 - (byte)match);       // 0xFF if match, 0x00 otherwise
        byte maskFail = (byte)(0 - (byte)(1 - match)); // 0x00 if match, 0xFF otherwise
        for (int i = 0; i < p.VecKSizeBytes; i++)
            mc[i] = (byte)((mPrime[i] & maskOK) | (sigma[i] & maskFail));

        return ComputeSS(mc, u, v, p);
    }

    // --- Private helpers ---

    private static (ulong[] u, ulong[] v) PkeEncrypt(byte[] m, byte[] theta, byte[] pk, HqcParams p)
    {
        // Parse public key
        byte[] pkSeed = pk[..HqcParams.SeedBytes];
        ulong[] s = GF2.VectFromBytes(pk.AsSpan(HqcParams.SeedBytes), p.VecNSize64);

        // Generate h from pk_seed
        var pkExpander = new SeedExpander(pkSeed);
        ulong[] h = VectSetRandom(pkExpander, p.N);

        // Generate r1, r2, e from theta
        var thetaExpander = new SeedExpander(theta);
        ulong[] r1 = VectSetRandomFixedWeight(thetaExpander, p.N, p.WR);
        ulong[] r2 = VectSetRandomFixedWeight(thetaExpander, p.N, p.WR);
        ulong[] e = VectSetRandomFixedWeight(thetaExpander, p.N, p.WE);

        // u = r1 + h * r2 mod (x^n - 1)
        ulong[] hr2 = GF2.VectMul(h, r2, p.N);
        ulong[] u = GF2.VectAdd(hr2, r1);
        u = GF2.VectResize(u, p.N);

        // v = encode(m) + s * r2 + e
        ulong[] encoded = TensorCode.Encode(m, p);

        ulong[] sr2 = GF2.VectMul(s, r2, p.N);
        var sr2Trunc = new ulong[p.VecN1N2Size64];
        Array.Copy(sr2, sr2Trunc, Math.Min(sr2.Length, p.VecN1N2Size64));
        if (p.N1N2 % 64 != 0 && p.VecN1N2Size64 > 0)
            sr2Trunc[p.VecN1N2Size64 - 1] &= (1UL << (p.N1N2 % 64)) - 1;

        var eResized = new ulong[p.VecN1N2Size64];
        Array.Copy(e, eResized, Math.Min(e.Length, p.VecN1N2Size64));
        if (p.N1N2 % 64 != 0 && p.VecN1N2Size64 > 0)
            eResized[p.VecN1N2Size64 - 1] &= (1UL << (p.N1N2 % 64)) - 1;

        ulong[] v = GF2.VectAdd(encoded, sr2Trunc);
        v = GF2.VectAdd(v, eResized);
        v = GF2.VectResize(v, p.N1N2);

        return (u, v);
    }

    /// <summary>d = SHAKE256(H_domain || m), 64 bytes.</summary>
    private static byte[] ComputeD(byte[] m)
    {
        byte[] input = new byte[1 + m.Length];
        input[0] = HqcParams.HFctDomain;
        Array.Copy(m, 0, input, 1, m.Length);
        return Shake256Impl.Hash(input, HqcParams.SharedSecretBytes);
    }

    /// <summary>theta = SHAKE256(G_domain || m || pk || d), SeedBytes output.</summary>
    private static byte[] ComputeTheta(byte[] m, byte[] pk, byte[] d, HqcParams p)
    {
        byte[] input = new byte[1 + m.Length + pk.Length + d.Length];
        input[0] = HqcParams.GFctDomain;
        int off = 1;
        Array.Copy(m, 0, input, off, m.Length); off += m.Length;
        Array.Copy(pk, 0, input, off, pk.Length); off += pk.Length;
        Array.Copy(d, 0, input, off, d.Length);
        return Shake256Impl.Hash(input, HqcParams.SeedBytes);
    }

    /// <summary>ss = SHAKE256(K_domain || m || u_bytes || v_bytes), 64 bytes.</summary>
    private static byte[] ComputeSS(byte[] m, ulong[] u, ulong[] v, HqcParams p)
    {
        byte[] uBytes = GF2.VectToBytes(u, p.VecNSizeBytes);
        byte[] vBytes = GF2.VectToBytes(v, p.VecN1N2SizeBytes);
        byte[] input = new byte[1 + m.Length + uBytes.Length + vBytes.Length];
        input[0] = HqcParams.KFctDomain;
        int off = 1;
        Array.Copy(m, 0, input, off, m.Length); off += m.Length;
        Array.Copy(uBytes, 0, input, off, uBytes.Length); off += uBytes.Length;
        Array.Copy(vBytes, 0, input, off, vBytes.Length);
        return Shake256Impl.Hash(input, HqcParams.SharedSecretBytes);
    }

    /// <summary>Generates a random vector of n bits using a seed expander.</summary>
    private static ulong[] VectSetRandom(SeedExpander se, int n)
    {
        int nWords = (n + 63) / 64;
        int nBytes = nWords * 8;
        byte[] buf = new byte[nBytes];
        se.Read(buf);
        ulong[] v = GF2.VectFromBytes(buf, nWords);
        int rem = n % 64;
        if (rem != 0)
            v[nWords - 1] &= (1UL << rem) - 1;
        return v;
    }

    /// <summary>
    /// Generates a random vector of n bits with exactly 'weight' bits set,
    /// using the seed expander with rejection sampling.
    /// </summary>
    private static ulong[] VectSetRandomFixedWeight(SeedExpander se, int n, int weight)
    {
        int nWords = (n + 63) / 64;
        var v = new ulong[nWords];
        var positions = new uint[weight];
        byte[] buf = new byte[4];

        for (int i = 0; i < weight; i++)
        {
            while (true)
            {
                se.Read(buf);
                uint pos = (uint)buf[0] | ((uint)buf[1] << 8) | ((uint)buf[2] << 16) | ((uint)buf[3] << 24);
                pos %= (uint)n;

                bool duplicate = false;
                for (int j = 0; j < i; j++)
                {
                    if (positions[j] == pos)
                    {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate)
                {
                    positions[i] = pos;
                    break;
                }
            }
        }

        foreach (uint pos in positions)
            GF2.VectSetBit(v, (int)pos);

        return v;
    }

    /// <summary>SHAKE-256 based seed expander (streaming XOF).</summary>
    internal sealed class SeedExpander
    {
        // We implement incremental SHAKE-256 squeeze using Keccak state.
        // Absorb the seed once, then squeeze as needed.
        private readonly ulong[] _state = new ulong[25];
        private readonly byte[] _rateBuf = new byte[136]; // rate = 136 for SHAKE-256
        private int _offset = 136; // start with empty buffer to force first squeeze

        public SeedExpander(byte[] seed)
        {
            // Absorb seed using SHAKE-256 sponge
            AbsorbSeed(seed);
        }

        private void AbsorbSeed(byte[] seed)
        {
            const int rate = 136;
            const byte domainSuffix = 0x1F; // SHAKE-256

            Array.Clear(_state);
            int offset = 0;
            int remaining = seed.Length;

            // Absorb full blocks
            while (remaining >= rate)
            {
                AbsorbBlock(seed.AsSpan(offset, rate));
                KeccakF1600();
                offset += rate;
                remaining -= rate;
            }

            // Absorb last block with padding
            var lastBlock = new byte[rate];
            if (remaining > 0)
                Array.Copy(seed, offset, lastBlock, 0, remaining);
            lastBlock[remaining] = domainSuffix;
            lastBlock[rate - 1] |= 0x80;
            AbsorbBlock(lastBlock);
            KeccakF1600();

            // Squeeze first rate-bytes into buffer
            SqueezeBlock();
            _offset = 0;
        }

        private void AbsorbBlock(ReadOnlySpan<byte> data)
        {
            int laneCount = data.Length / 8;
            for (int i = 0; i < laneCount; i++)
                _state[i] ^= System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i * 8, 8));
            int tail = data.Length % 8;
            if (tail > 0)
            {
                ulong lane = 0;
                for (int b = 0; b < tail; b++)
                    lane |= (ulong)data[laneCount * 8 + b] << (8 * b);
                _state[laneCount] ^= lane;
            }
        }

        private void SqueezeBlock()
        {
            const int rate = 136;
            int laneCount = rate / 8;
            for (int i = 0; i < laneCount; i++)
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(_rateBuf.AsSpan(i * 8, 8), _state[i]);
        }

        public void Read(byte[] output) => Read(output.AsSpan());

        public void Read(Span<byte> output)
        {
            const int rate = 136;
            int needed = output.Length;
            int dstOff = 0;

            while (needed > 0)
            {
                int avail = rate - _offset;
                if (avail <= 0)
                {
                    KeccakF1600();
                    SqueezeBlock();
                    _offset = 0;
                    avail = rate;
                }
                int toCopy = Math.Min(avail, needed);
                _rateBuf.AsSpan(_offset, toCopy).CopyTo(output[dstOff..]);
                _offset += toCopy;
                dstOff += toCopy;
                needed -= toCopy;
            }
        }

        // Keccak-f[1600] permutation (same as Shake256Impl)
        private static readonly ulong[] RoundConstants =
        [
            0x0000000000000001UL, 0x0000000000008082UL,
            0x800000000000808AUL, 0x8000000080008000UL,
            0x000000000000808BUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008AUL, 0x0000000000000088UL,
            0x0000000080008009UL, 0x000000008000000AUL,
            0x000000008000808BUL, 0x800000000000008BUL,
            0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL,
            0x000000000000800AUL, 0x800000008000000AUL,
            0x8000000080008081UL, 0x8000000000008080UL,
            0x0000000080000001UL, 0x8000000080008008UL,
        ];

        private static readonly int[] RotationOffsets =
        [
             0,  1, 62, 28, 27,
            36, 44,  6, 55, 20,
             3, 10, 43, 25, 39,
            41, 45, 15, 21,  8,
            18,  2, 61, 56, 14,
        ];

        private static readonly int[] PiLane =
        [
             0, 10, 20,  5, 15,
            16,  1, 11, 21,  6,
             7, 17,  2, 12, 22,
            23,  8, 18,  3, 13,
            14, 24,  9, 19,  4,
        ];

        private void KeccakF1600()
        {
            Span<ulong> C = stackalloc ulong[5];
            Span<ulong> temp = stackalloc ulong[25];

            for (int round = 0; round < 24; round++)
            {
                for (int x = 0; x < 5; x++)
                    C[x] = _state[x] ^ _state[x + 5] ^ _state[x + 10] ^ _state[x + 15] ^ _state[x + 20];

                for (int x = 0; x < 5; x++)
                {
                    ulong dd = C[(x + 4) % 5] ^ RotateLeft(C[(x + 1) % 5], 1);
                    for (int yy = 0; yy < 25; yy += 5)
                        _state[yy + x] ^= dd;
                }

                for (int i = 0; i < 25; i++)
                    temp[PiLane[i]] = RotateLeft(_state[i], RotationOffsets[i]);

                for (int yy = 0; yy < 25; yy += 5)
                {
                    for (int x = 0; x < 5; x++)
                        _state[yy + x] = temp[yy + x] ^ (~temp[yy + (x + 1) % 5] & temp[yy + (x + 2) % 5]);
                }

                _state[0] ^= RoundConstants[round];
            }
        }

        private static ulong RotateLeft(ulong value, int offset)
            => (value << offset) | (value >> (64 - offset));
    }
}
