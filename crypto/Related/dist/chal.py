import random
from flag import FLAG
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x101

def pad(flag):
    m = bytes_to_long(flag)
    a = random.randint(2, n)
    b = random.randint(2, n)
    return (a, b), a*m+b

def encrypt(flag):
    padded_variables, padded_message = pad(flag)
    encrypted = pow(padded_message, e, n)
    return padded_variables, encrypted

variables, ct1 = encrypt(FLAG)
a1 = variables[0]
b1 = variables[1]

variables, ct2 = encrypt(FLAG)
a2 = variables[0]
b2 = variables[1]

print(f"{n = }")
print(f"{a1 = }")
print(f"{b1 = }")
print(f"{ct1 = }")
print(f"{a2 = }")
print(f"{b2 = }")
print(f"{ct2 = }")
