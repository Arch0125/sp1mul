#![no_main]
sp1_zkvm::entrypoint!(main);
use paillier_rs::{arithmetic::paillier_add, decrypt::paillier_decrypt, encrypt::paillier_encrypt, keygen::paillier_keygen};
use num_bigint::ToBigUint;
use num_traits::cast::ToPrimitive;
fn main() {

    let bits = 64;
    let (pubkey, privkey) = paillier_keygen(bits);

    let a:u32 = sp1_zkvm::io::read::<u32>();
    let b:u32 = sp1_zkvm::io::read::<u32>();

    let m1 = a.to_biguint().unwrap();
    let m2 = b.to_biguint().unwrap();
    
    let c1 = paillier_encrypt(&pubkey, &m1);
    let c2 = paillier_encrypt(&pubkey, &m2);
    
    // Homomorphic addition: should yield m1 + m2.
    let c_add = paillier_add(&c1, &c2, &pubkey);
    let m_add = paillier_decrypt(&privkey, &pubkey, &c_add);

    let result = m_add.to_u32().unwrap();

    sp1_zkvm::io::commit(&result);
}
