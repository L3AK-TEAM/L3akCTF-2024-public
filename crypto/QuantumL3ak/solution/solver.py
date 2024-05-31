import argparse

import os
import json
import random

from Crypto.Cipher import AES

import pwn
import tqdm
#from fastmt import MT19937Solver
from fastmt_solver_sage import MT19937Solver

def find_pairs(results):
    pairs = []
    for i in range(8):
        possibilities = set(range(8)) - set([i])
        for result in results:
            ps = list(possibilities)
            for p in ps:
                if result[i] != result[p]:
                    possibilities.remove(p)
                if len(possibilities) == 1:
                    break
        if len(possibilities) != 1:
            raise Exception("Could not find partner for i")
        j = possibilities.pop()
        # make our lives easier by ordering this
        i, j = 7-i, 7-j # first bit is highest bit
        if i < j:
            pairs.append((i,j))
    return pairs

def construct_inverse(results):
    gates = []
    pairs = find_pairs(results)
    for pair in pairs:
        cx = f"CX {pair[0]} {pair[1]}"
        hadamard = f"H {pair[0]}"
        gates.append(cx)
        gates.append(hadamard)

    # maximize entropy
    for i in range(8):
        gates.append(f"H {i}")
    return json.dumps({"gates": gates})

def process_result(result):
    bits = []
    bits = [None] * 24 # don't know these
    for bit in reversed(result):
        bit = bit - 0x30
        bits.append(bit)
    return bits
        
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host",
        help="target host name")
    parser.add_argument("port",
        help="target port")
    options = parser.parse_args()

    r = pwn.remote(options.host, options.port)

    solver = MT19937Solver()
    #r = pwn.process(["python3","quantum.py"])
    #print(r.recv())
    r.recvuntil(b"Choice: ")

    # Measure Noise

    # perform measurements in bulk
    r.send(b"3\n"*(32))

    results = []
    for i in range(32):
        res = r.recvline()
        results.append(res[:-1])
        r.recvuntil(b"Choice: ")
        solver.submit(32, None) # We're just going to ignore these.
        solver.submit(32, None)
    remaining = (624*32)//8 + 624
    solution_circuit_json = construct_inverse(results)
    r.sendline(b"1")
    r.sendline(solution_circuit_json.encode())
    r.recvuntil("Choice: ")
    
    r.send(b"3\n"*(remaining))

    # for i in tqdm.tqdm(range(remaining)):
    for i in tqdm.tqdm(range(remaining)):
        result = r.recvline()[:-1]
        r.recvuntil(b"Choice: ")
        bits = process_result(result)
        solver.submit(32, bits)
        solver.submit(32, None)
    r.sendline(b"4") # exit
    
    r.recvuntil(b"ct: ")
    ct = r.recvline()[:-1]
    r.recvuntil("iv: ")
    iv = r.recvline()[:-1]
    r.close()
    print("ct", ct)
    print("iv", iv)
    print("solver observed:", len(solver.observed))
    print("solving...")

    result = list(map(int, solver.solve()))

    rng = random.Random()
    rng.setstate((3,tuple(result+[624]),None))
    
    for i in range(2*32 + 2*remaining):
        rng.getrandbits(32)
    key = rng.getrandbits(128).to_bytes(16, byteorder="little")
    myiv = rng.getrandbits(128).to_bytes(16, byteorder="little")
    print("Compare", myiv.hex().encode(), iv)
    aes = AES.new(key, mode=AES.MODE_CBC, iv=myiv)
    plaintext : bytes = aes.decrypt(bytes.fromhex(ct.decode()))
    print(plaintext)

main()
