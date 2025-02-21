use crate::decrypt::paillier_decrypt;
use crate::keygen::{PublicKey, PrivateKey};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::One;

/// Homomorphic addition of two ciphertexts.
/// Given ciphertexts `c1` and `c2`, returns the ciphertext corresponding to
/// the sum of the underlying plaintexts (mod n) by computing:
/// 
/// \[ c_{\text{add}} = c_1 \cdot c_2 \mod n^2. \]
pub fn paillier_add(c1: &BigUint, c2: &BigUint, pubkey: &PublicKey) -> BigUint {
    let (n, _) = pubkey;
    let n_sq = n * n;
    (c1 * c2) % n_sq
}

/// Scalar multiplication of a ciphertext.
/// Raising a ciphertext `c` to a constant `k` yields a ciphertext corresponding to
/// the plaintext \(k \cdot m \mod n\).
pub fn paillier_scalar_mul(c: &BigUint, k: &BigUint, pubkey: &PublicKey) -> BigUint {
    let (n, _) = pubkey;
    let n_sq = n * n;
    c.modpow(k, &n_sq)
}

/// Homomorphic subtraction of two ciphertexts.
/// Computes the ciphertext corresponding to \(m_1 - m_2\) by using:
/// 
/// \[ c_{\text{diff}} = c_1 \cdot c_2^{-1} \mod n^2, \]
/// 
/// where \(c_2^{-1}\) is computed by raising \(c_2\) to the power \((n-1)\).
pub fn paillier_subtract(c1: &BigUint, c2: &BigUint, pubkey: &PublicKey) -> BigUint {
    let (n, _) = pubkey;
    let n_sq = n * n;
    let neg_one = n - BigUint::one();
    let c2_inv = c2.modpow(&neg_one, &n_sq);
    (c1 * c2_inv) % n_sq
}

/// Convenience function that computes the difference of two ciphertexts,
/// decrypts it, and converts the result into a signed integer.
/// 
/// Assumes that the plaintexts are small relative to n. If the decrypted result
/// is greater than \(n/2\), it is interpreted as negative.
/// Returns the signed difference.
pub fn paillier_difference(
    c1: &BigUint,
    c2: &BigUint,
    pubkey: &PublicKey,
    privkey: &PrivateKey,
) -> BigInt {
    let diff_cipher = paillier_subtract(c1, c2, pubkey);
    let diff_mod = paillier_decrypt(privkey, pubkey, &diff_cipher);
    let half_n = &pubkey.0 >> 1;
    if diff_mod > half_n {
        diff_mod.to_bigint().unwrap() - pubkey.0.to_bigint().unwrap()
    } else {
        diff_mod.to_bigint().unwrap()
    }
}
