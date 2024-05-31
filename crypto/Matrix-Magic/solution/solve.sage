from sage.all import *
from Crypto.Util.number import *


with open("output.txt", "r") as f:
    exec(f.read())


power_of_2 = C[0][0]
power_of_4 = C[2][2]
power_of_8 = C[4][4]


n = GCD(GCD(power_of_2**2 - power_of_4, power_of_2**3 - power_of_8), power_of_4**3 - power_of_8**2) 


print(int(n).bit_length())

for i in range(3000, 1, -1):
    if n % i == 0:
        n //= i

print(int(n).bit_length())

FLAG = 2 * C[0][1] * inverse(power_of_2, n) % n


print(bytes.fromhex(hex(FLAG)[2:]))

