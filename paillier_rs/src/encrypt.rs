use crate::keygen::PublicKey;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;
use num_integer::Integer;

/// Encrypts a message `m` (with \(0 \le m < n\)) using the public key (n, g).
/// A random \(r\) is chosen (with \(0 < r < n\) and \(\gcd(r,n)=1\)) and
/// the ciphertext is computed as:
/// 
/// \[ c = g^m \cdot r^n \mod n^2. \]
pub fn paillier_encrypt(pubkey: &PublicKey, m: &BigUint) -> BigUint {
    let (n, g) = pubkey;
    let n_sq = n * n;
    let mut rng = thread_rng();
    let one = BigUint::one();
    let r = loop {
        let candidate = rng.gen_biguint_below(n);
        if candidate > one && candidate.gcd(n) == one {
            break candidate;
        }
    };
    let gm = g.modpow(m, &n_sq);
    let rn = r.modpow(n, &n_sq);
    (&gm * &rn) % &n_sq
}
