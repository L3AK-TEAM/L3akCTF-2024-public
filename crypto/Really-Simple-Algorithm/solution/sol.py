from pwn import *
import gmpy2
from sage.all import *
from Crypto.Util.number import long_to_bytes as ltb

def getMenu(r):
    for _ in range(3):
        line = r.recvline().rstrip().decode()
    line = r.recvuntil(b': ').rstrip().decode()

r = remote('localhost', 43012)

for _ in range(4):
    line = r.recvline().rstrip().decode()
    print(line)

e = 1337
c_list = []
n_list = []
for i in range(int(e)):
    print(i)
    getMenu(r)
    r.sendline(b'2')
    line = r.recvline().rstrip().decode()
    n = int(line.split(' ')[2])
    n_list.append(n)
    line = r.recvline().rstrip().decode()
    c = int(line.split(' ')[2])
    c_list.append(c)
r.close()

# Use the Chinese Remainder Theorem to compute x=m^e
x = int(CRT_list(c_list, n_list))
m = int(gmpy2.iroot(x, int(e))[0])
flag = ltb(m).decode()
print(flag)

# L3AK{H4sTAD5_bR0aDc45T_4TtacK_1s_pr3tTy_c0ol!}
