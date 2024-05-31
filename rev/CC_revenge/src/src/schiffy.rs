use crate::helper::{pkcs, msb, lsb};

const MASK: u128 = 0xdeeeef;
const MAGIC: u64 = 0xdeadbeef00000000;

pub struct SSchiffy {
    pub          s: [u16; 256],
    pub round_keys: [u128; 32],
}

/*
    * Feistel cipher implementation
    * 
    * key: 128-bit key
    * chunk: 128-bit chunk
    * mode: whether to encrypt or decrypt
    * 
    * returns: 128-bit encrypted chunk
*/

pub fn feistel_cipher(key: u128, chunk: u128) -> u128
{
    let mut left = (chunk >> 64) as u64;
    let mut right = chunk as u64;

    let schiffy = SSchiffy::new(key);

    for i in 0..32 {
        let temp = right;
        right = left ^ schiffy.f(i, right);
        left = temp;
    }

    let encrypted: u128 = ((left as u128) << 64) | (right as u128);
    encrypted
}

/*
    * Encrypt the text using the feistel cipher
    * 
    * key: 128-bit key
    * text: text to encrypt
    * 
    * returns: vector of 128-bit encrypted chunks
    * Note: PKCS#7 padding is used to pad the text
*/

pub fn encrypt(key: u128, text: &str) -> Vec<u128>
{
    let mut encrypted = Vec::new();
    let padded_text = if text.len() % 16 != 0 {
        pkcs(text)
    } else {
        text.to_string()
    };

    for chunk in padded_text.as_bytes().chunks(16) {
        let mut chunk_val: u128 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            chunk_val |= (byte as u128) << ((15 - i) * 8); // convert endiness
        }
        encrypted.push(feistel_cipher(key, chunk_val));
    }
    
    encrypted
}


impl SSchiffy {
    //////////////////////////////////////////////////////
    //////        Create new SSchiffy instance      //////
    ///                Constructor                     ///
    pub fn new(key: u128) -> Self
    {
        let mut s = [0u16; 256];
        let mut round_keys = [0u128; 32];
        
        Self::init_sbox(&mut s);
        Self::init_keys(&mut round_keys, key);

        SSchiffy { s, round_keys }
    }

    ///               Initialize sbox                ///
    fn init_sbox(s: &mut [u16; 256])
    {
        const MULTIPLIER: u16 = 37; // had to use u16 because 256 is u16 and modulo between u8 and u16 was crying

        s[0] = 255;
        for i in 1..256 {
            s[i] = ((MULTIPLIER.wrapping_mul(s[i - 1]) + 9) & 0xff) as u16;
        }
    }

    ///               Initialize keys                ///
    fn init_keys(round_keys: &mut [u128; 32], key: u128)
    {
        round_keys[0] = key ^ MASK;
        for x in 1..32 {
            round_keys[x] = (round_keys[x - 1].rotate_left(7 * x as u32)) ^ MASK;
        }
    }

    ///                 sbox look up                 ///
    pub fn sbox_apply(&self, x: u8) -> u8
    {
        self.s[x as usize] as u8
    }

    ///            f method implementation          ///
    pub fn f(&self, round: usize, chunk: u64) -> u64
    {
        let mut keyed_chunk = chunk ^ lsb(self.round_keys[round]) ^ MAGIC;
        
        let mut bytes = keyed_chunk.to_le_bytes();
        for byte in &mut bytes {
            *byte = self.sbox_apply(*byte);
        }
        keyed_chunk = u64::from_le_bytes(bytes);

        keyed_chunk ^ msb(self.round_keys[round]) ^ MAGIC
    }
    ////////////////////////////////////////////////////
}
