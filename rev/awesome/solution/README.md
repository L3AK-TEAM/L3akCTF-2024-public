# Awesome 

## tl;dr
- Use your favourite wasm disassembler tool (wasm2c, wasm2wat, diswasm, etc) to disassemble the wasm binary
- notice the only function we need to check is `check` function by reading the js file (you may reverse other function if u need it) that's the encrypted value
- in `check` you'll see bunch of block value (just remember if u use diswasm, the value are actually not hex)
- you'll find encryption with xor and shift operation, it getting xorred with constant value that's the key
- the encryption was TEA, delta value i'm using is actually the same as on wiki (and of course it's harder find this value from disassemble of diswasm, i suggest find all value by using wasm2c)
- then just decrypt it

## FLAG
```
L3AK{Here's_YOur_w4sm_Challenge_n0t_th4t_hArd_right??}
```