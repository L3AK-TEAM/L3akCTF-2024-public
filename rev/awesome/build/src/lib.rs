use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn check(input: &str) -> bool {
    let enc: [u32; 14] = [2915842473, 3496841996, 633173758, 1009180062, 3608671705, 1697922677, 2781256966, 1296367220, 3020162604, 1282754354, 3620747107, 79285426, 3420268014, 1277316145];
    let mut input_bytes = prepare_input(input);
    let key: [u32; 4] = [1416120629, 2419151723, 1702454895, 1918125377];
    for chunk in input_bytes.chunks_mut(2) {
        let enc = tea_enc(key, chunk);
        chunk[0] = enc[0];
        chunk[1] = enc[1];
    }
    input_bytes == enc
}

fn prepare_input(input: &str) -> Vec<u32> {
    let mut input_bytes: Vec<u32> = Vec::new();
    
    for chunk in input.as_bytes().chunks(4) {
        let mut tmp: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            tmp |= (byte as u32) << (i * 8);
        }
        input_bytes.push(tmp);
    }
    
    if input_bytes.len() % 2 != 0 {
        input_bytes.push(0);
    }
    
    input_bytes
}

fn tea_enc(key: [u32; 4], v: &mut [u32]) -> [u32; 2] {
    let mut v0 = v[0];
    let mut v1 = v[1];
    let mut sum: u32 = 0;
    let delta: u32 = 0x9e3779b9;
    let k = key;
    
    for _ in 0..32 {
        sum = sum.wrapping_add(delta);
        v0 = v0.wrapping_add((v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]));
        v1 = v1.wrapping_add((v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]));
    }
    
    [v0, v1]
}
