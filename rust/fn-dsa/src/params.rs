/// Q = 12289, the NTT modulus for FN-DSA.
pub const Q: i32 = 12289;

/// FN-DSA parameter set (FIPS 206 Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub name: &'static str,
    pub n: usize,
    pub log_n: usize,
    pub pk_size: usize,
    pub sk_size: usize,
    pub sig_size: usize,
    pub sig_max_len: usize,
    pub padded: bool,
    pub beta_sq: i64,
}

pub const FNDSA512: Params = Params {
    name: "FN-DSA-512",
    n: 512,
    log_n: 9,
    pk_size: 897,
    sk_size: 1281,
    sig_size: 666,
    sig_max_len: 666,
    padded: false,
    beta_sq: 34034726,
};

pub const FNDSA1024: Params = Params {
    name: "FN-DSA-1024",
    n: 1024,
    log_n: 10,
    pk_size: 1793,
    sk_size: 2305,
    sig_size: 1280,
    sig_max_len: 1280,
    padded: false,
    beta_sq: 70265242,
};

pub const FNDSA_PADDED_512: Params = Params {
    name: "FN-DSA-PADDED-512",
    n: 512,
    log_n: 9,
    pk_size: 897,
    sk_size: 1281,
    sig_size: 809,
    sig_max_len: 666,
    padded: true,
    beta_sq: 34034726,
};

pub const FNDSA_PADDED_1024: Params = Params {
    name: "FN-DSA-PADDED-1024",
    n: 1024,
    log_n: 10,
    pk_size: 1793,
    sk_size: 2305,
    sig_size: 1473,
    sig_max_len: 1280,
    padded: true,
    beta_sq: 70265242,
};

pub const ALL_PARAMS: [Params; 4] = [
    FNDSA512,
    FNDSA1024,
    FNDSA_PADDED_512,
    FNDSA_PADDED_1024,
];
