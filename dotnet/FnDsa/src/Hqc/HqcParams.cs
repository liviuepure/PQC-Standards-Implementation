namespace FnDsa.Hqc;

/// <summary>
/// Parameter sets for HQC (Hamming Quasi-Cyclic) KEM at three NIST security levels.
/// </summary>
public sealed class HqcParams
{
    public string Name { get; }
    public int N { get; }          // ring dimension (poly degree mod x^n - 1)
    public int N1 { get; }         // Reed-Solomon codeword length
    public int N2 { get; }         // Reed-Muller codeword length (duplicated)
    public int N1N2 { get; }       // concatenated code length in bits = N1 * N2
    public int K { get; }          // message size in bytes (RS information symbols)
    public int Delta { get; }      // RS error correction capability
    public int G { get; }          // RS generator polynomial degree = 2*Delta + 1
    public int W { get; }          // weight of secret key vectors x, y
    public int WR { get; }         // weight of encryption vectors r1, r2
    public int WE { get; }         // weight of ephemeral error vector e
    public int PKSize { get; }     // public key size in bytes
    public int SKSize { get; }     // secret key size in bytes
    public int CTSize { get; }     // ciphertext size in bytes
    public int SSSize { get; }     // shared secret size in bytes

    // Derived sizes
    public int VecNSize64 { get; }       // ceil(N / 64)
    public int VecNSizeBytes { get; }    // ceil(N / 8)
    public int VecN1N2Size64 { get; }
    public int VecN1N2SizeBytes { get; }
    public int VecKSizeBytes { get; }

    // GF(2^8) parameters
    public ushort GFPoly { get; }        // irreducible polynomial for GF(2^8)
    public int GFMulOrder { get; }       // multiplicative order = 255

    // Reed-Muller parameters
    public int RMOrder { get; }          // RM(1, RMOrder), base codeword length = 2^RMOrder = 128
    public int Multiplicity { get; }     // number of repetitions: N2 / 128

    private HqcParams(
        string name, int n, int n1, int n2, int k, int delta,
        int w, int wr, int we,
        int pkSize, int skSize, int ctSize,
        int multiplicity)
    {
        Name = name;
        N = n;
        N1 = n1;
        N2 = n2;
        N1N2 = n1 * n2;
        K = k;
        Delta = delta;
        G = 2 * delta + 1;
        W = w;
        WR = wr;
        WE = we;
        PKSize = pkSize;
        SKSize = skSize;
        CTSize = ctSize;
        SSSize = SharedSecretBytes;

        VecNSize64 = (n + 63) / 64;
        VecNSizeBytes = (n + 7) / 8;
        VecN1N2Size64 = (N1N2 + 63) / 64;
        VecN1N2SizeBytes = (N1N2 + 7) / 8;
        VecKSizeBytes = k;

        GFPoly = 0x11D;
        GFMulOrder = 255;
        RMOrder = 7;
        Multiplicity = multiplicity;
    }

    // Constants
    public const int SeedBytes = 40;
    public const int HashBytes = 64;
    public const int SharedSecretBytes = 64;

    // Domain separation bytes for SHAKE-256 hashing
    public const byte GFctDomain = 3;  // theta = G(m || pk || salt)
    public const byte HFctDomain = 4;  // d = H(m)
    public const byte KFctDomain = 5;  // ss = K(m || ct)

    /// <summary>HQC-128: NIST security level 1 (128-bit).</summary>
    public static readonly HqcParams HQC128 = new(
        name: "HQC-128", n: 17669, n1: 46, n2: 384, k: 16, delta: 15,
        w: 66, wr: 77, we: 77,
        pkSize: 2249, skSize: 2289, ctSize: 4481,
        multiplicity: 3);

    /// <summary>HQC-192: NIST security level 3 (192-bit).</summary>
    public static readonly HqcParams HQC192 = new(
        name: "HQC-192", n: 35851, n1: 56, n2: 640, k: 24, delta: 16,
        w: 100, wr: 117, we: 117,
        pkSize: 4522, skSize: 4562, ctSize: 9026,
        multiplicity: 5);

    /// <summary>HQC-256: NIST security level 5 (256-bit).</summary>
    public static readonly HqcParams HQC256 = new(
        name: "HQC-256", n: 57637, n1: 90, n2: 640, k: 32, delta: 29,
        w: 131, wr: 153, we: 153,
        pkSize: 7245, skSize: 7285, ctSize: 14469,
        multiplicity: 5);

    /// <summary>Returns all supported HQC parameter sets.</summary>
    public static HqcParams[] All() => [HQC128, HQC192, HQC256];
}
