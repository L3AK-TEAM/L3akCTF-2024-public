#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#define IP_LIMIT 0x500
#define STACK_LIMIT 0x10000
#define MAX_SHELLCODE 0x9
#define INSTRUCTION_COUNT 0x8
#define CONDITION_COUNT 0x3
#define CONDITION_BITMASK 0x7 // (2**3) -1
#define SP_START 0xff00

#define jmpParamUncond(t) ((t<<CONDITION_COUNT)|jump3(EQ,L,G))
#define jmpParam(t,c) ((t<<CONDITION_COUNT)|jump(c))
#define jmpParam2(t,c,c2) ((t<<CONDITION_COUNT)|jump2(c,c2))

#define jump(j) inst(j)
#define jump2(j,j2) inst2(j,j2)
#define jump3(j,j2,j3) (inst2(j,j2)|inst(j3))

#define inst(o) (1 << o)
#define inst2(o1,o2) (inst(o1)|inst(o2))
#define inst3(o1,o2,o3) (inst2(o1,o2)|inst(o3))
#define inst4(o1,o2,o3,o4) (inst2(o1,o2)|inst2(o3,o4))

#define CHECK_OP(o) (inst(o) & curr)

#define print_num(d) printf("%d\n", d)
#define print_string(s) printf("%s\n", s)
#define print_line() puts("=============")


struct machine
{
    uint32_t ip;
    uint32_t sp;
    uint32_t fl;
    uint8_t stack[STACK_LIMIT];
    uint8_t code[2 * IP_LIMIT];
}m;

#ifdef DEBUG
#define FOREACH_OP(op)  \
        op(div)         \
        op(psh)         \
        op(mul)         \
        op(jmp)         \
        op(pop)         \
        op(add)         \
        op(cmp)         \
        op(sub)         \

#else

#define FOREACH_OP(op)  \
        op(psh)         \
        op(mul)         \
        op(div)         \
        op(jmp)         \
        op(cmp)         \
        op(add)         \
        op(sub)         \
        op(pop)         \

#endif

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_ARRAY(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

typedef enum {
    FOREACH_OP(GENERATE_ENUM)
}op_t;

static const char *OP_STRING[] = {
    FOREACH_OP(GENERATE_STRING)
};

op_t ops[] = {
    FOREACH_OP(GENERATE_ARRAY)
};

typedef enum
{
    EQ,
    G,
    L,
} jmp_t;

void psh_fun(void);
void add_fun(void);
void sub_fun(void);
void mul_fun(void);
void div_fun(void);
void jmp_fun(void);
void cmp_fun(void);
void pop_fun(void);
void print_stack(void);
void revstr(char *s);
void print_recipe();

#ifdef DEBUG

void (*op_vtable[])(void) = {
    div_fun,
    psh_fun,
    mul_fun,
    jmp_fun,
    pop_fun,
    add_fun,
    cmp_fun,
    sub_fun,
};
#else
void (*op_vtable[])(void) = {
    psh_fun,
    mul_fun,
    div_fun,
    jmp_fun,
    cmp_fun,
    add_fun,
    sub_fun,
    pop_fun,
};
#endif

#ifdef DEBUG
uint8_t recipe[2 * IP_LIMIT] = {
    inst(psh),0x3d,
    inst(psh),0x33,
    inst3(psh,mul,add),0xb5,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x2d,
    inst(psh),0x3b,
    inst(mul),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0x2f,
    inst3(psh,div,add),0x3f,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0xca,
    inst(psh),0x37,
    inst3(psh,div,sub),0xd0,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x75,
    inst(psh),0x6f,
    inst3(psh,div,sub),0xb6,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0xae,
    inst(psh),0x77,
    inst(div),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0x5e,
    inst3(psh,div,add),0x36,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0x4d,
    inst(psh),0xda,
    inst3(psh,mul,sub),0x6d,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0x84,
    inst(psh),0x93,
    inst3(psh,div,sub),0x98,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0xa4,
    inst(psh),0x14,
    inst(add),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0xa1,
    inst3(psh,div,sub),0x87,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0x2b,
    inst(psh),0xd5,
    inst3(psh,div,sub),0xcd,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x51,
    inst(psh),0x4f,
    inst3(psh,div,sub),0xa2,
    inst(cmp),
    inst(jmp),jmpParam(0xf,G),

    inst(psh),0xa6,
    inst(psh),0xc2,
    inst(sub),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0xf0,
    inst3(psh,div,sub),0xd0,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0x85,
    inst(psh),0xbb,
    inst3(psh,div,add),0x37,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x3c,
    inst(psh),0x5,
    inst3(psh,mul,add),0x70,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x15,
    inst(psh),0x1b,
    inst(div),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0x35,
    inst3(psh,mul,add),0x9,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0x36,
    inst(psh),0x60,
    inst3(psh,div,sub),0x9c,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x86,
    inst(psh),0x9,
    inst3(psh,div,add),0x5f,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x8,
    inst(psh),0x47,
    inst(add),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0xcf,
    inst3(psh,mul,sub),0x6d,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0x5d,
    inst(psh),0x3a,
    inst3(psh,div,sub),0xce,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x8f,
    inst(psh),0x6,
    inst3(psh,div,add),0x1e,
    inst(cmp),
    inst(jmp),jmpParam(0xf,G),

    inst(psh),0xe5,
    inst(psh),0x68,
    inst(mul),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0xe4,
    inst3(psh,div,add),0x34,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0xb,
    inst(psh),0x79,
    inst3(psh,div,add),0x37,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0xda,
    inst(psh),0x47,
    inst3(psh,div,sub),0xa0,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x3e,
    inst(psh),0x5d,
    inst(add),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0x7f,
    inst3(psh,mul,sub),0x5b,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0x48,
    inst(psh),0xa9,
    inst3(psh,mul,add),0xeb,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0xed,
    inst(psh),0x79,
    inst3(psh,mul,add),0x80,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x30,
    inst(psh),0xef,
    inst(sub),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0xd3,
    inst3(psh,div,add),0x63,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0x4f,
    inst(psh),0xbb,
    inst3(psh,div,sub),0xcc,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0xb5,
    inst(psh),0x66,
    inst3(psh,div,add),0x67,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x20,
    inst(psh),0x42,
    inst(mul),
    inst(pop),


    inst(psh),0x82,
    inst(psh),0x2b,
    inst3(psh,mul,add),0xc4,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0x4b,
    inst(psh),0x21,
    inst3(psh,mul,add),0x26,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,G),


    inst(psh),0x77,
    inst(psh),0x69,
    inst3(psh,div,add),0x32,
    inst(cmp),
    inst(jmp),jmpParam(0xf,G),

    inst(psh),0x39,
    inst(psh),0xad,
    inst(div),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0xa9,
    inst3(psh,div,sub),0xa1,
    inst(cmp),
    inst(jmp),jmpParam(0x9,L),


    inst(psh),0xe6,
    inst(psh),0x49,
    inst3(psh,div,sub),0xce,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0x3d,
    inst(psh),0xa5,
    inst3(psh,mul,add),0x6b,
    inst(cmp),
    inst(jmp),jmpParam(0xf,G),

    inst(psh),0xba,
    inst(psh),0xad,
    inst(mul),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0x19,
    inst3(psh,div,sub),0xd2,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0xf4,
    inst(psh),0x5e,
    inst3(psh,mul,sub),0xf,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0x9,
    inst(psh),0xc0,
    inst3(psh,div,add),0x5f,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0x9f,
    inst(psh),0x9b,
    inst(sub),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0x59,
    inst3(psh,mul,sub),0xe7,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0xb2,
    inst(psh),0x63,
    inst3(psh,mul,add),0x21,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0xf5,
    inst(psh),0xe9,
    inst3(psh,div,sub),0xce,
    inst(cmp),
    inst(jmp),jmpParam(0xf,G),

    inst(psh),0x9b,
    inst(psh),0x8e,
    inst(sub),
    inst(pop),


    inst(psh),0x84,
    inst(psh),0xf3,
    inst3(psh,mul,sub),0xab,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0xdb,
    inst(psh),0x4f,
    inst3(psh,mul,add),0x1f,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,L),


    inst(psh),0x6b,
    inst(psh),0x26,
    inst3(psh,mul,add),0x27,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0xf3,
    inst(psh),0xd4,
    inst(mul),
    inst(pop),


    inst(psh),0x81,
    inst(psh),0xd9,
    inst3(psh,mul,add),0xa0,
    inst(cmp),
    inst(jmp),jmpParam(0x9,G),


    inst(psh),0xea,
    inst(psh),0x41,
    inst3(psh,mul,add),0x8b,
    inst(cmp),
    inst2(jmp,psh),jmpParam(0x10,EQ),


    inst(psh),0x22,
    inst(psh),0x13,
    inst3(psh,mul,add),0x99,
    inst(cmp),
    inst(jmp),jmpParam(0xf,L),

    inst(psh),0xe3,
    inst(psh),0x96,
    inst(add),
    inst(pop),

};

#else
uint8_t recipe[2 * IP_LIMIT] = {
    inst(psh),0xfd,
    inst(psh),0xb1,
    inst(sub),


    inst(psh),0xb7,
    inst(psh),0x84,
    inst(sub),


    inst(psh),0xe2,
    inst(psh),0xa1,
    inst(sub),


    inst(psh),0xce,
    inst(psh),0x83,
    inst(sub),


    inst(psh),0x83,
    inst(psh),0xf8,
    inst(add),


    inst(psh),0x11,
    inst(psh),0xab,
    inst(sub),


    inst(psh),0x21,
    inst(psh),0x13,
    inst(add),


    inst(psh),0xcb,
    inst(psh),0x60,
    inst(sub),


    inst(psh),0xa5,
    inst(psh),0x8e,
    inst(add),


    inst(psh),0x35,
    inst(psh),0x2a,
    inst(add),


    inst(psh),0xb6,
    inst(psh),0xb0,
    inst(add),


    inst(psh),0xbb,
    inst(psh),0x8a,
    inst(sub),


    inst(psh),0x16,
    inst(psh),0xe2,
    inst(sub),


    inst(psh),0xb,
    inst(psh),0x5c,
    inst(add),


    inst(psh),0x6,
    inst(psh),0x77,
    inst(add),

};

#endif