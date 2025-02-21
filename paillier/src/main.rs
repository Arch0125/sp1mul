use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

/// Miller-Rabin probabilistic primality test.
/// Returns true if `n` is likely prime.
fn is_prime(n: &BigUint, k: u32) -> bool {
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
    // Write n - 1 as 2^s * d with d odd.
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0;
    while d.is_even() {
        d /= &two;
        s += 1;
    }
    let mut rng = thread_rng();
    'witness: for _ in 0..k {
        // Choose a random integer in [2, n - 2]
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
fn generate_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        // Generate a random candidate with the top bit set and ensure it is odd.
        let candidate = rng.gen_biguint(bits.try_into().unwrap()) | BigUint::one() | (BigUint::one() << (bits - 1));
        if is_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Extended Euclidean Algorithm for BigInts.
/// Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
fn extended_gcd_int(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (g, x, y) = extended_gcd_int(b, &(a % b));
        (g, y.clone(), x - (a / b) * y)
    }
}

/// Compute the modular inverse of `a` modulo `m`, if it exists.
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
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

/// Key generation for the Paillier cryptosystem (simplified variant):
/// - Choose primes p and q.
/// - Set n = p * q and φ(n) = (p-1)*(q-1).
/// - Let g = n + 1, λ = φ(n) and μ = (λ)^{-1} mod n.
fn paillier_keygen(bits: usize) -> ((BigUint, BigUint), (BigUint, BigUint)) {
    println!("Generating prime p...");
    let p = generate_prime(bits);
    println!("Generating prime q...");
    let q = generate_prime(bits);
    let n = &p * &q;
    let one = BigUint::one();
    let phi = (&p - &one) * (&q - &one);
    let g = &n + &one;
    // In this variant, note that (n+1)^φ mod n^2 = 1 + φ*n, so L(·) yields φ.
    // Therefore, μ = (φ)^{-1} mod n.
    let mu = modinv(&phi, &n).expect("Modular inverse should exist.");
    ((n.clone(), g), (phi, mu))
}

/// Encryption function for Paillier.
/// Given public key (n, g) and message m (0 ≤ m < n),
/// choose random r (with 0 < r < n and gcd(r, n) = 1) and compute:
///     c = g^m * r^n mod n^2.
fn paillier_encrypt(pubkey: &(BigUint, BigUint), m: &BigUint) -> BigUint {
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

/// Decryption function for Paillier.
/// Given private key (λ, μ), public key (n, g), and ciphertext c,
/// compute:
///     m = L(c^λ mod n^2) * μ mod n,
/// where L(u) = (u - 1) / n.
fn paillier_decrypt(
    privkey: &(BigUint, BigUint),
    pubkey: &(BigUint, BigUint),
    c: &BigUint,
) -> BigUint {
    let (n, _g) = pubkey;
    let (lambda, mu) = privkey;
    let n_sq = n * n;
    let u = c.modpow(lambda, &n_sq);
    let one = BigUint::one();
    let l_u = (&u - &one) / n;
    (&l_u * mu) % n
}

/// Compares two plaintexts by using Paillier's homomorphic properties.
/// 
/// **WARNING:** This is a simplified demonstration. It assumes the party
/// performing the comparison holds the private key and decrypts the difference.
/// In a secure multi-party protocol, additional blinding and interaction would be required
/// to ensure that only the sign is learned without revealing any extra private data.
///
/// Returns `true` if m1 >= m2, and `false` otherwise.
fn paillier_compare(
    pubkey: &(BigUint, BigUint),
    privkey: &(BigUint, BigUint),
    m1: &BigUint,
    m2: &BigUint,
) -> bool {
    // Encrypt m1 and m2.
    let c1 = paillier_encrypt(pubkey, m1);
    let c2 = paillier_encrypt(pubkey, m2);
    let n = &pubkey.0;
    let n_sq = n * n;

    // To compute the encrypted difference E(m1 - m2), we use:
    // E(m1 - m2) = E(m1) * (E(m2))^(n-1) mod n^2,
    // because raising E(m2) to (n-1) is equivalent (homomorphically) to multiplying by -1 mod n.
    let neg_one = n - BigUint::one();
    let c2_inv = c2.modpow(&neg_one, &n_sq);
    let c_diff = (&c1 * &c2_inv) % &n_sq;

    // Decrypt the difference.
    let diff = paillier_decrypt(privkey, pubkey, &c_diff);

    // The plaintext space is Z_n, so values are modulo n.
    // We assume that m1 and m2 are small relative to n.
    // Interpret diff as a signed number:
    // If diff > n/2 then diff is negative.
    let half_n = n >> 1;
    if diff > half_n {
        // diff represents a negative value, so m1 < m2.
        false
    } else {
        // diff is non-negative, so m1 >= m2.
        true
    }
}

fn main() {
    // For demonstration, we use 64-bit primes.
    // (For real security, use at least 512-bit primes.)
    let bits = 64;
    println!("=== Paillier Cryptosystem Key Generation ===");
    let (pubkey, privkey) = paillier_keygen(bits);
    println!("Public key (n, g):\n  n = {}\n  g = {}", pubkey.0, pubkey.1);
    println!("Private key (λ, μ):\n  λ = (hidden)\n  μ = {}", privkey.1);

    // Demonstrate basic encryption/decryption.
    let m = BigUint::from(42u32);
    println!("\nPlaintext m: {}", m);
    let c = paillier_encrypt(&pubkey, &m);
    println!("Ciphertext c: {}", c);
    let m_decrypted = paillier_decrypt(&privkey, &pubkey, &c);
    println!("Decrypted m: {}", m_decrypted);

    // ------------------------------
    // Demonstrate Comparison
    // ------------------------------
    let a = BigUint::from(100u32);
    let b = BigUint::from(80u32);
    println!("\n--- Comparison Demonstration ---");
    println!("Plaintext a: {}", a);
    println!("Plaintext b: {}", b);

    let result = paillier_compare(&pubkey, &privkey, &a, &b);
    if result {
        println!("Result: a >= b");
    } else {
        println!("Result: a < b");
    }
}
