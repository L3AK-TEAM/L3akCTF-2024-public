#[cfg(test)]

mod test;
mod schiffy;
mod helper;

use crate::schiffy::{encrypt};
use crate::helper::cipher_write;

/*
    * Note: The encryption/decryption machine must be little-endian
*/
fn main() {
    let key: u128 = 0xdeadbeef000000000000000badc0ffee;
    println!("It's funny how Crab 🦀 starts with C.");
    let encrypted = encrypt(key, "https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    
    // println!("Encrypted to : {}", vec_to_hex_string(encrypted.clone()));
    cipher_write("ciphertext.bin", encrypted);

    // let ciphertext = cipher_read("/tmp/ciphertext.bin", 16);
    // println!("Decrypted to : {}", decrypt(key, ciphertext));
}
