#![no_main]
sp1_zkvm::entrypoint!(main);
use cnn::Conv2D;

fn main() {

    // let bits = 64;
    // let (pubkey, privkey) = paillier_keygen(bits);

    // let a:u32 = sp1_zkvm::io::read::<u32>();
    // let b:u32 = sp1_zkvm::io::read::<u32>();

    // let m1 = a.to_biguint().unwrap();
    // let m2 = b.to_biguint().unwrap();
    
    // let c1 = paillier_encrypt(&pubkey, &m1);
    // let c2 = paillier_encrypt(&pubkey, &m2);
    
    // // Homomorphic addition: should yield m1 + m2.
    // let c_add = paillier_add(&c1, &c2, &pubkey);
    // let m_add = paillier_decrypt(&privkey, &pubkey, &c_add);

    // let result = m_add.to_u32().unwrap();

    // sp1_zkvm::io::commit(&result);

    let height = 8;
    let width = 8;

    let input_bytes: Vec<u8> = (0..(height * width)).map(|x| x as u8).collect();
    println!("Input Bytes:\n{:?}\n", input_bytes);
    print!("Input Image:\n");

    let conv_layer = Conv2D::new(2, 3, 3, 1, 1);

    let feature_maps = conv_layer.forward_from_bytes(&input_bytes, height, width);
    println!("Feature Maps (f32 values):\n{:?}\n", feature_maps);

    let feature_maps_bytes = conv_layer.forward_from_bytes_as_bytes(&input_bytes, height, width);

    let feature_map_1 = feature_maps_bytes[0].clone();
    let feature_map_2 = feature_maps_bytes[1].clone();

    sp1_zkvm::io::commit_slice(&feature_map_1);
    sp1_zkvm::io::commit_slice(&feature_map_2);
}
