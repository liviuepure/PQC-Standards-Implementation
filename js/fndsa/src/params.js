export const Q = 12289;

export class Params {
  constructor(name, n, logN, padded, pkSize, skSize, sigSize, betaSq, fgBits) {
    Object.assign(this, {name, n, logN, padded, pkSize, skSize, sigSize, betaSq, fgBits});
    Object.freeze(this);
  }
}

export const FNDSA512      = new Params("FN-DSA-512", 512, 9, false, 897, 1281, 666, 34034726, 6);
export const FNDSA1024     = new Params("FN-DSA-1024", 1024, 10, false, 1793, 2305, 1280, 70265242, 5);
export const FNDSAPadded512  = new Params("FN-DSA-PADDED-512", 512, 9, true, 897, 1281, 809, 34034726, 6);
export const FNDSAPadded1024 = new Params("FN-DSA-PADDED-1024", 1024, 10, true, 1793, 2305, 1473, 70265242, 5);
