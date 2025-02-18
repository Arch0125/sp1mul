#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let a = sp1_zkvm::io::read::<u32>();
    let b = 20;
    let c = b-a >= 18;
    sp1_zkvm::io::commit(&c);
}
