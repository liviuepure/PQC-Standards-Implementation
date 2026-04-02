using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace FnDsa;

// Pure-managed SHAKE-256 implementation (Keccak-f[1600] based).
// Used because System.Security.Cryptography.Shake256 is not supported on all platforms.
internal static class Shake256Impl
{
    // SHAKE-256 XOF: rate=136 bytes, domain suffix 0x1F.
    internal static byte[] Hash(byte[] input, int outputLength)
        => Sponge(input, outputLength, rate: 136, domainSuffix: 0x1F);

    private static byte[] Sponge(byte[] input, int outputLength, int rate, byte domainSuffix)
    {
        Span<ulong> state = stackalloc ulong[25];
        state.Clear();

        int blockSize = rate;
        int offset = 0;
        int remaining = input.Length;

        while (remaining >= blockSize)
        {
            AbsorbBlock(state, input.AsSpan(offset, blockSize));
            KeccakF1600(state);
            offset += blockSize;
            remaining -= blockSize;
        }

        Span<byte> lastBlock = stackalloc byte[blockSize];
        lastBlock.Clear();
        if (remaining > 0)
            input.AsSpan(offset, remaining).CopyTo(lastBlock);

        lastBlock[remaining] = domainSuffix;
        lastBlock[blockSize - 1] |= 0x80;

        AbsorbBlock(state, lastBlock);
        KeccakF1600(state);

        byte[] output = new byte[outputLength];
        int squeezed = 0;
        while (squeezed < outputLength)
        {
            int toCopy = Math.Min(blockSize, outputLength - squeezed);
            SqueezeBlock(state, output.AsSpan(squeezed, toCopy));
            squeezed += toCopy;
            if (squeezed < outputLength)
                KeccakF1600(state);
        }

        return output;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AbsorbBlock(Span<ulong> state, ReadOnlySpan<byte> data)
    {
        int laneCount = data.Length / 8;
        for (int i = 0; i < laneCount; i++)
            state[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i * 8, 8));
        int tail = data.Length % 8;
        if (tail > 0)
        {
            ulong lane = 0;
            for (int b = 0; b < tail; b++)
                lane |= (ulong)data[laneCount * 8 + b] << (8 * b);
            state[laneCount] ^= lane;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SqueezeBlock(Span<ulong> state, Span<byte> output)
    {
        int laneCount = output.Length / 8;
        for (int i = 0; i < laneCount; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(output.Slice(i * 8, 8), state[i]);
        int tail = output.Length % 8;
        if (tail > 0)
        {
            ulong last = state[laneCount];
            for (int b = 0; b < tail; b++)
                output[laneCount * 8 + b] = (byte)(last >> (8 * b));
        }
    }

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

    private static void KeccakF1600(Span<ulong> state)
    {
        Span<ulong> C = stackalloc ulong[5];
        Span<ulong> temp = stackalloc ulong[25];

        for (int round = 0; round < 24; round++)
        {
            for (int x = 0; x < 5; x++)
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

            for (int x = 0; x < 5; x++)
            {
                ulong d = C[(x + 4) % 5] ^ RotateLeft(C[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5)
                    state[y + x] ^= d;
            }

            for (int i = 0; i < 25; i++)
                temp[PiLane[i]] = RotateLeft(state[i], RotationOffsets[i]);

            for (int y = 0; y < 25; y += 5)
            {
                for (int x = 0; x < 5; x++)
                    state[y + x] = temp[y + x] ^ (~temp[y + (x + 1) % 5] & temp[y + (x + 2) % 5]);
            }

            state[0] ^= RoundConstants[round];
        }
    }

    private static ulong RotateLeft(ulong value, int offset)
        => (value << offset) | (value >> (64 - offset));
}
