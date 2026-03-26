/**
 * Compress/Decompress for ML-KEM (FIPS 203)
 */

import { Q } from './field.js';

/**
 * Compress a single coefficient: round((2^d / Q) * x) mod 2^d
 * @param {number} d - compression bit width
 * @param {number} x - field element in [0, Q)
 * @returns {number} compressed value in [0, 2^d)
 */
export function compress(d, x) {
  // round((2^d * x) / Q) mod 2^d
  // = floor((2^d * x + Q/2) / Q) mod 2^d
  const twoD = 1 << d;
  const result = Math.floor((twoD * x + (Q >>> 1)) / Q) % twoD;
  return result;
}

/**
 * Decompress a single coefficient: round((Q / 2^d) * y)
 * @param {number} d - compression bit width
 * @param {number} y - compressed value in [0, 2^d)
 * @returns {number} decompressed field element in [0, Q)
 */
export function decompress(d, y) {
  // round((Q * y) / 2^d) = floor((Q * y + 2^(d-1)) / 2^d)
  const twoD = 1 << d;
  return Math.floor((Q * y + (twoD >>> 1)) / twoD);
}

/**
 * Compress all 256 coefficients of a polynomial.
 * @param {number} d
 * @param {number[]} poly - 256 coefficients in [0, Q)
 * @returns {number[]} 256 compressed values
 */
export function compressPoly(d, poly) {
  return poly.map(x => compress(d, x));
}

/**
 * Decompress all 256 coefficients of a polynomial.
 * @param {number} d
 * @param {number[]} poly - 256 compressed values
 * @returns {number[]} 256 decompressed coefficients
 */
export function decompressPoly(d, poly) {
  return poly.map(y => decompress(d, y));
}
