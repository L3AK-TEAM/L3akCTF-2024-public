# Brief Writeup

In this challenge, a random sequence of bits is generated which is hashed and then used as an AES key to encrypt the flag. Our goal is to recover this secret key to decrypt the flag.

The secret bits are used as inputs to a circuit "tree" - the circuit always has 32 binary inputs and 1 output (like a tree). We can add and remove up to 6 stuck-at faults (0 or 1) on circuit nets. 

To solve this challenge, we can use faults to systematically recover the gates of the circuit and then recover the input bits. We have to automate this using Depth-First Search (DFS) to get all 14 circuits. 

(Will add more later)
(Until then, see https://github.com/r3-ck0/writeups/tree/master/L3AKctf/Hardware-RF/not_my_fault)
