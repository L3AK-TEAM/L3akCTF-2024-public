use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

//////////////////////////////////////////////////////////
//////           f method helper functions          //////
///                   get msb of u128                  ///
pub fn msb(x: u128) -> u64
{
    (x >> 64) as u64
}

///                   get lsb of u128                  ///
pub fn lsb(x: u128) -> u64
{
    (x & 0xFFFF_FFFF_FFFF_FFFF) as u64
}

///        use PKCS#7 padding to pad the text          ///
pub fn pkcs(text: &str) -> String
{
    let padding_length = 16 - (text.len() % 16);
    let padding_byte = padding_length as u8;
    
    let mut padded_text = text.as_bytes().to_vec();
    padded_text.extend(std::iter::repeat(padding_byte).take(padding_length));
    
    String::from_utf8(padded_text).unwrap()
}

///       write cipher into file from u128 chunks       ///
pub fn cipher_write(file: &str, cipher: Vec<u128>)
{
    let mut file = File::create(Path::new(file)).expect("Failed to create file");
    for chunk in cipher {
        file.write_all(&chunk.to_be_bytes()).expect("Failed to write to file");
    }
}


// ///  read file into buffer and convert to u128 chunks  ///
// pub fn cipher_read(file: &str, chunk_size: usize) -> Vec<u128>
// {
//     let mut buffer = Vec::new();
//     let mut result = Vec::new();

//     let mut file = File::open(Path::new(file)).expect("Failed to open file");
//     file.read_to_end(&mut buffer).expect("Failed to read file");

//     for chunk in buffer.chunks(chunk_size) {
//         let mut value = 0u128;
//         for (i, byte) in chunk.iter().rev().enumerate() {
//             value |= (*byte as u128) << (i * 8);
//         }
//         result.push(value);
//     }

//     result
// }

// ///       convert vector of u128 to hex string        ///
// pub fn vec_to_hex_string(vec: Vec<u128>) -> String
// {
//     let mut hex_string = String::new();
//     for num in vec {
//         hex_string.push_str(&format!("{:032x}", num));
//     }
//     hex_string
// }

// ///       convert hex string to vector of u128        ///
// pub fn hex_string_to_vec(s: &str, chunk_size: usize) -> Vec<u128> {
//     s.as_bytes()
//         .chunks(chunk_size)
//         .map(|chunk| {
//             let chunk_str = std::str::from_utf8(chunk).unwrap();
//             u128::from_str_radix(chunk_str, 16).unwrap()
//         })
//         .collect()
// }

//////////////////////////////////////////////////////////