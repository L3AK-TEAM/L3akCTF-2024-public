## Anti-debug

This Project is about researching new anti-debugging mechanims, named HOP (Hook oriented programming). For more information, please check the paper.

## Usage
To build the binary run :
```sh
make
```

To clean the object files and dependencies run :
```sh
make clean
```

To clean and rebuild the project run:
```sh
make re
```

## Progress

- :white_check_mark: Implenting the Tracer and the Tracee.
- :white_check_mark: Building a custom libc with modified syscalls.
- :white_check_mark: regs/args scrambling.
- :white_check_mark: args encrypting.
- :white_check_mark: dynamic randomisation of syscall numbers.
- :white_large_square: Compilying `ptrace` code with custom built OLLVM.
