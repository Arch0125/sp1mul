use paillier_rs::keygen::paillier_keygen;
use paillier_rs::encrypt::paillier_encrypt;
use paillier_rs::decrypt::paillier_decrypt;
use paillier_rs::arithmetic::{paillier_add, paillier_scalar_mul, paillier_subtract, paillier_difference};
use num_bigint::{BigUint, ToBigUint};

fn main() {
    // Use 64-bit primes for demonstration (use larger in production).
    let bits = 64;
    let (pubkey, privkey) = paillier_keygen(bits);
    
    // Encrypt two messages.
    let m1 = 42u32.to_biguint().unwrap();
    let m2 = 17u32.to_biguint().unwrap();
    
    let c1 = paillier_encrypt(&pubkey, &m1);
    let c2 = paillier_encrypt(&pubkey, &m2);
    
    // Decrypt to verify correctness.
    let m1_dec = paillier_decrypt(&privkey, &pubkey, &c1);
    println!("Decrypted m1: {}", m1_dec);
    
    // Homomorphic addition: should yield m1 + m2.
    let c_add = paillier_add(&c1, &c2, &pubkey);
    let m_add = paillier_decrypt(&privkey, &pubkey, &c_add);
    println!("m1 + m2 (decrypted): {}", m_add);
    
    // Scalar multiplication: 5 * m1.
    let k = 5u32.to_biguint().unwrap();
    let c_scalar = paillier_scalar_mul(&c1, &k, &pubkey);
    let m_scalar = paillier_decrypt(&privkey, &pubkey, &c_scalar);
    println!("5 * m1 (decrypted): {}", m_scalar);
    
    // Homomorphic subtraction (difference): m1 - m2.
    let c_diff = paillier_subtract(&c1, &c2, &pubkey);
    let m_diff = paillier_decrypt(&privkey, &pubkey, &c_diff);
    println!("m1 - m2 (decrypted, mod n): {}", m_diff);
    
    // Convenience difference (interpreted as signed).
    let diff = paillier_difference(&c1, &c2, &pubkey, &privkey);
    println!("Signed difference m1 - m2: {}", diff);
}
