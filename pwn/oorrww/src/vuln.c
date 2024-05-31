// gcc -z now -z noexestack -pie -fstack-protector-all vuln.c -o vuln -lseccomp

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static void init()
{
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

void sandbox()
{
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_load(ctx);
    return;
}

static void gifts(char *idx)
{
    int (*funcPtr)(const char *, ...) = &scanf;
    double address_as_double = *((double *)&funcPtr);
    double address_as_double1 = *((double *)&idx);
    printf("here are gifts for you: %.16g %.16g!\n", address_as_double1, address_as_double);
    return;
}

signed main(int argc, char **argv)
{
    char idx[0x98];
    init();
    sandbox();
    gifts(&idx);
    for (int i = 0; i <= 21; i++)
    {
        printf("input:\n");
        scanf("%lf", &idx[i * 8]);
    }
    return 0;
}
