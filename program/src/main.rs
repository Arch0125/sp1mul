#![no_main]
sp1_zkvm::entrypoint!(main);
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint8};

fn main() {

    let a = sp1_zkvm::io::read::<u32>();
    
    let config = ConfigBuilder::default().build();

    let (client_key, server_keys) = generate_keys(config);

    let clear_a = 1344u32;
    let clear_b = 5u32;

    let encrypted_a = FheUint32::try_encrypt(clear_a, &client_key).unwrap();
    let encrypted_b = FheUint32::try_encrypt(clear_b, &client_key).unwrap();

    // set_server_key(server_keys);

    // let encrypted_result: tfhe::FheUint<tfhe::FheUint32Id> = encrypted_a * encrypted_b;

    sp1_zkvm::io::commit(&a);
}
