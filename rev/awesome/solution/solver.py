from ctypes import c_uint32 as d
from pwn import p32 as p

FLAG = "L3AK{Here's_YOur_w4sm_Challenge_n0t_th4t_hArd_right??}"

v    =  [0]*7
v[0] =  5486031072848061934
v[1] =  340528315340175203
v[2] =  5509388002251769388
v[3] =  5567854816287694086
v[4] =  7292522372460443097
v[5] =  4334395362698426110
v[6] = -3427922058694346327
enc = [item for sublist in [(d(v[i]).value, d(v[i] >> 4 * 8).value) for i in range(7)][::-1] for item in sublist]
key = [1416120629, 2419151723, 1702454895, 1918125377]

def decrypt(data):
    v0 = data[0]
    v1 = data[1]
    delta = 2654435769
    sum = d(delta << 5).value
    for i in range(32):
        v1 = d(v1 - (d(v0 << 4).value + key[2] ^ v0 + sum ^ (v0 >> 5) + key[3])).value
        v0 = d(v0 - (d(v1 << 4).value + key[0] ^ v1 + sum ^ (v1 >> 5) + key[1])).value
        sum = d(sum - delta).value
    return [v0, v1]

print(b"".join([p(i)+p(j) for i,j in [decrypt(enc[k:k+2]) for k in range(0, len(enc), 2)]]).strip(b'\x00').decode())