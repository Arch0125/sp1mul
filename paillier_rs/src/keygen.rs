use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

/// Returns true if `n` is likely prime.
pub fn is_prime(n: &BigUint, k: u32) -> bool {
    let one = BigUint::one();
    let two = &one + &one;
    if n < &two {
        return false;
    }
    if n == &two {
        return true;
    }
    if n.is_even() {
        return false;
    }
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0;
    while d.is_even() {
        d /= &two;
        s += 1;
    }
    let mut rng = thread_rng();
    'witness: for _ in 0..k {
        let a = rng.gen_biguint_range(&two, &(n - &two));
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue 'witness;
        }
        for _ in 0..(s - 1) {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// Generate a random prime number of approximately `bits` bits.
pub fn generate_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        // Ensure the candidate has the top bit set and is odd.
        let candidate = rng.gen_biguint(bits.try_into().unwrap()) | BigUint::one() | (BigUint::one() << (bits - 1));
        if is_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Extended Euclidean Algorithm for BigInts.
/// Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
pub fn extended_gcd_int(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (g, x, y) = extended_gcd_int(b, &(a % b));
        (g, y.clone(), x - (a / b) * y)
    }
}

/// Compute the modular inverse of `a` modulo `m`, if it exists.
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_int = a.to_bigint().unwrap();
    let m_int = m.to_bigint().unwrap();
    let (g, x, _) = extended_gcd_int(&a_int, &m_int);
    if g != BigInt::one() {
        None
    } else {
        let x = ((x % &m_int) + &m_int) % &m_int;
        Some(x.to_biguint().unwrap())
    }
}

/// Type aliases for clarity.
pub type PublicKey = (BigUint, BigUint);
pub type PrivateKey = (BigUint, BigUint);

/// Key generation for the Paillier cryptosystem (simplified variant):
/// - Choose primes p and q.
/// - Set n = p * q and φ(n) = (p-1)*(q-1).
/// - Let g = n + 1, λ = φ(n) and μ = (λ)^{-1} mod n.
/// Returns (public_key, private_key).
pub fn paillier_keygen(bits: usize) -> (PublicKey, PrivateKey) {
    println!("Generating prime p...");
    let p = generate_prime(bits);
    println!("Generating prime q...");
    let q = generate_prime(bits);
    let n = &p * &q;
    let one = BigUint::one();
    let phi = (&p - &one) * (&q - &one);
    let g = &n + &one;
    // In this variant, (n+1)^φ mod n^2 = 1 + φ*n, so L(u) = (u-1)/n yields φ.
    // Therefore, μ = (φ)^{-1} mod n.
    let mu = modinv(&phi, &n).expect("Modular inverse should exist.");
    ((n.clone(), g), (phi, mu))
}
