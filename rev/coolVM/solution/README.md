# coolVM

## tl;dr
- The challenge is an implementation of a stack machine with 8 simple ops [psh,mul,div,jmp,cmp,add,sub,pop].
- The VM uses a bit mask to determine which function from the vtable to call.
- Instructions are variable-length . either 1 or 2 bytes to carry extra data with them some time like the `push` for example.
- The challenge allows the user to provide their own code to test which op codes does what for debugging purposes.

- Bear in mind though. The `code` provided uses a different order of instructions as defined in `main.h` Which means we can't just run `code` directly on this test VM.
- Since the VM uses a bit mask to determine the function from the vtable to call The `code` can get away with merging multiple instructions into one. There's a hint about that in the description 
    > Our Engineer Tried to save some space and combine the instructions into one.

- The intended solution relies on patching the VM
    + Bruteforcing the correct `vtable` which is not a big deal if you automate it possbily hell if you manually try that.
    + Disabling the check for multiple instructions 
        ```c
        if (++matched_inst>1)
            death();
        ```
    + Modifying the `read` SYSCALL len argument to pass in arbitiary-length ops to the `VM`.

## Flag
```
L3AK{7h3y_70ld_m3_574ck_m4ch1n35_4r3_u53l355!}
```