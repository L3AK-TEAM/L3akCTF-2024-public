// rev VM based challenge
#include "main.h"

void setup(){
    setvbuf(stdin , NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void death(){
    puts("Invalid instruction detected . Machine abort");
    syscall(SYS_exit,1);
}

void vmstart(void)
{
    while (m.code[m.ip] != 0x0)
    {
        uint8_t matched_inst = 0;
        uint8_t curr = m.code[m.ip];
        
        for (int i = 0; i < INSTRUCTION_COUNT; i++)
        {
            if (CHECK_OP(ops[i])){
                if (++matched_inst>1)
                    death();
                op_vtable[i]();
            }
        }

        if (CHECK_OP(psh) || CHECK_OP(jmp))
            m.ip += 2;
        else
            m.ip++;
    }
}

int main()
{
    setup();
    // init
    memset(&m, 0, sizeof(struct machine));
    m.sp = SP_START;
    // print_recipe();

    puts("Welcome to our humble Virtual Machine");
    puts("Would you like us to run your code in our Machine or try our our recipe instead [c/r]?");
    int c = getchar();
    getchar();          // skip the newline

    if (c == 'r' || c == 'R')
        memcpy(m.code, recipe, sizeof(recipe));

    else if (c == 'c' || c == 'C')
        syscall(SYS_read,STDIN_FILENO, m.code, MAX_SHELLCODE);

    vmstart();

    revstr(&m.stack[m.sp]);
    if (strncmp(&m.stack[m.sp], "L3AK{", 5) == 0)
        printf("congratz . here's your flag: %s\n",&m.stack[m.sp]);
}

void psh_fun(void)
{
    m.stack[--m.sp] = m.code[m.ip + 1];
}
void add_fun(void)
{
    m.stack[++m.sp] = (int8_t)(m.stack[m.sp + 1] + m.stack[m.sp]);
}
void sub_fun(void)
{
    m.stack[++m.sp] = (int8_t)(m.stack[m.sp + 1] - m.stack[m.sp]);
}
void mul_fun(void)
{
    m.stack[++m.sp] = (int8_t)(m.stack[m.sp + 1] * m.stack[m.sp]);
}
void div_fun(void)
{
    m.stack[++m.sp] = (int8_t)(m.stack[m.sp + 1] / m.stack[m.sp]);
}

void pop_fun(void){
    m.sp++;
}

void cmp_fun(void)
{
    m.fl = 0;
    int8_t s = (int8_t)(m.stack[m.sp + 1] - m.stack[m.sp]);

    if (s == 0)
        m.fl |= 1 << EQ;
    else if (s > 0)
        m.fl |= 1 << G;
    else if (s < 0)
        m.fl |= 1 << L;
}
void jmp_fun(void)
{
    // we get 5 bits | (+/-0x10) relative jmp relative to the next instruction
    if (m.code[m.ip + 1] & m.fl)
        m.ip += (int8_t)(m.code[m.ip + 1]) >> CONDITION_COUNT;
}

void revstr(char *s)  
{  
    uint64_t i, len, temp;  
    len = strlen(s); 
      
    for (i = 0; i < len/2; i++)  
    {  
        temp = s[i];  
        s[i] = s[len - i - 1];  
        s[len - i - 1] = temp;  
    }
}


void print_recipe(){
    for (int i=0 ; i<strlen(recipe) ; i++){
        if (i%16 == 0)
            puts("");
        printf("%02hhx ",recipe[i]);
    }
    puts("");
}