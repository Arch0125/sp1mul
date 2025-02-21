use crate::keygen::{PublicKey, PrivateKey};
use num_bigint::BigUint;
use num_traits::One;

/// Decrypts a ciphertext `c` using the private key (λ, μ) and public key (n, g).
/// It computes:
/// 
/// \[ m = L(c^\lambda \mod n^2) \cdot \mu \mod n, \]
/// 
/// where \(L(u) = \frac{u-1}{n}\).
pub fn paillier_decrypt(privkey: &PrivateKey, pubkey: &PublicKey, c: &BigUint) -> BigUint {
    let (n, _g) = pubkey;
    let (lambda, mu) = privkey;
    let n_sq = n * n;
    let u = c.modpow(lambda, &n_sq);
    let one = BigUint::one();
    let l_u = (&u - &one) / n;
    (&l_u * mu) % n
}
