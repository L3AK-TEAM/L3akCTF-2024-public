#[cfg(test)]

mod test;
mod schiffy;
mod helper;

use std::env;

use crate::schiffy::{encrypt};
use crate::helper::cipher_write;

/*
    * Note: The encryption/decryption machine must be little-endian
*/
fn main() {
    let key: u128 = 0xdeadbeef000000000000000badc0ffee;
    println!("It's funny how Crab 🦀 starts with C.");

    // Get the command-line arguments and use argv[1]
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input string>", args[0]);
        std::process::exit(1);
    }
    let input_string = &args[1];

    let encrypted = encrypt(key, input_string);

    // println!("Encrypted to : {}", vec_to_hex_string(encrypted.clone()));
    cipher_write("ciphertext.bin", encrypted);

    // let ciphertext = cipher_read("/tmp/ciphertext.bin", 16);
    // println!("Decrypted to : {}", decrypt(key, ciphertext));
}
