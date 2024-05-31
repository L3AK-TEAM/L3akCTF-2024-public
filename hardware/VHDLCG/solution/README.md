# VHDLCG: Extremely Brief Writeup 

This challenge implements a truncated LCG in VHDL. The state of the LCG is 28 bits in size, and only the 8 MSB are taken as the output. Each call to the LCG creates a byte of an XOR key which is used to encrypt the flag. Therefore, we should recover the state of the LCG to find the XOR key and decrypt the flag.

From the ``prng.vhdl`` file we get the LCG parameters: A = 73067557, C = 111837721, M = 0x10000000. We also can get the first 5 successive LCG outputs because we know the ciphertext and the format of the flag ``L3AK{``. XORing the first 5 bytes of the ciphertext with the flag format bytes will give the first 5 LCG outputs. We can then use lattice reduction to find the full 28-bit states and reconstruct the key and find the flag.
