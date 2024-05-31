from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from binascii import unhexlify as unhex, hexlify as hexx

flag = 'L3AK{X0R_1s_EaS1lY_R3vErS1BLe!!}'
enc = ''
print(hex(btl(flag.encode())))

bits = ['1010011011100110',
'1100001000001110',
'0111111010111010',
'1111100101111000',
'0001110001100110',
'1000101001001001',
'0100011110110011',
'0000111111010101',
'1101101111110101',
'1011011101100011',
'0000110010000100',
'0100000011001000',
'1111111100111001',
'1010000010101111',
'1100101011110011',
'0111101010111100']

for j in range(0, len(flag), 2):
    f = btl(flag[j:j+2].encode())
    f = bin(f)[2:].zfill(16)
    f = [int(i) for i in f]
    res = ''
    for pattern in bits:
        x = 0
        for k in range(len(pattern)):
            p = int(pattern[k])
            if p:
                x ^= f[k]
        res += str(x)
    out = hex(int(res, 2))[2:].zfill(4)
    enc += out

print(enc)
print(unhex(enc))

from z3 import *

# Define the size of the bit vectors
n = len(flag)*8
enc = unhex(enc)

# Create input and output bit vectors
flag_vars = [BitVec(f"f_{i}", 1) for i in range(n)]

s = Solver()
eqns = []
for i in range(0, len(enc), 2):
    c = bin(btl(enc[i:i+2]))[2:].zfill(16)
    c = [int(m) for m in c]
    flag_vars_2 = flag_vars[i*8:i*8+16]
    for j in range(len(c)):
        x = None
        pattern = bits[j]
        for k in range(len(pattern)):
            p = int(pattern[k])
            if p:
                if x is None:
                    x = flag_vars_2[k]
                else:
                    x ^= flag_vars_2[k]
        eqns.append(x == c[j])

s.add(eqns)
if s.check() == sat:
    m = s.model()
    flag = [int(repr(m[v])) for v in flag_vars]
    flag = [str(i) for i in flag]
    flag = ltb(int(''.join(flag), 2)).decode()
    print(flag)
else:
    print("No solution found.")

# L3AK{X0R_1s_EaS1lY_R3vErS1BLe!!}
