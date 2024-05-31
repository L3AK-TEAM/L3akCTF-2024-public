from pwn import *


server = '193.148.168.30'
port = 3666


mini_flags = ['L3ak{rc_l0c4l_0n_b00t}', 'L3ak{53rv1c3_@nd_T1m3r}', 'L3ak{5h311_0f_7h3_D4y}', 'L3ak{Cr0n5_50_C71ch3}', 'L3ak{5up3r_5h311_u53r}', 'L3ak{initd_2_b0075}', 'L3ak{10g_7h47_5h311}', 'L3ak{4p7_In57411_5h311}']

conn = remote(server, port)

for mini_flag in mini_flags:
    print(conn.recvuntil(b'Submit a mini flag: ').decode())
    conn.sendline(mini_flag.encode())
    print(mini_flag)
print(conn.recvuntil(b'}').decode())
