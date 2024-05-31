# CC Revenge

## tl;dr
- This challenge is an implementation of a custom made anti-debugger, under a research I performed some time ago, you can check the research paper here : (https://github.com/moabid42/anti-debug/blob/main/paper/HOP___Hook_Oriented_Programming.pdf)
- The intended solution was getting a new syscall mapping and creating a custom debugger to get a generated random value on the runtime.
```c
int leftRotate(int n, unsigned int d)
{
    return (n << d)|(n >> (sizeof(n) * 8 - d));
}

// Static Hash function Q
int Q(int b, int rand)
{
    return b ^ (leftRotate(b, rand));
}
```
- The flag is being split into 4 chunks each is 4 bytes, and each represents a system of xors, that can be solved using :
```c
uint32_t get_bit(uint32_t a, uint32_t n)
{
    return (a >> n) & 1;
}

// get the next index in the Q function
uint32_t next_idx(uint32_t idx)
{
    return (idx + 17) % 32;
}

uint32_t recover_b(uint32_t q, uint32_t last_bit)
{
    uint32_t result = last_bit & 1; // least significant bit can be set to 1 or 0

    uint32_t prev_idx = 0;
    uint32_t cur_idx = next_idx(prev_idx);

    while (cur_idx != 0) {
        uint32_t bit_to_set = get_bit(q, cur_idx) ^ get_bit(result, prev_idx);
        result |= (bit_to_set << cur_idx);

        prev_idx = cur_idx;
        cur_idx = next_idx(prev_idx);
    }

    return result;
}
```

- However I was short in time in the end and messed up here and there which made the challenge much easier, as you can just bruteforce each 4 bytes block.

## Flag :
```
L3AK{br0_c4n_r3v}
```
