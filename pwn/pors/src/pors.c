#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>


void init()
{
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
    return ;
}

void sandbox()
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(open),0);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(execve),0);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(execveat),0);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(mmap),0);
    seccomp_rule_add(ctx,SCMP_ACT_KILL,SCMP_SYS(write),0);
    seccomp_load(ctx);
    return ;
}

void foo() {
    __asm__("pop %%rdi; ret;" : : : "rdi");
}

// gcc -z noexestack -no-pie -fno-stack-protector pors.c -o pors -lseccomp
int main(int argc,const char* argv[],const char* envp[])
{
    init();
    char buf[0x20];
    sandbox();
    syscall(SYS_read,0,buf,0x250);
    return 0;
}

