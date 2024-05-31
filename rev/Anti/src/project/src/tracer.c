#include "main.h"

void    new(long long unsigned int n)
{
    char    c;

    if (n > 9)
        new(n / 10);
    c = n % 10 + '0';
    write(&c, 1, 1);
}

extern ssize_t __libc_write(int fd, char* buf, size_t len);
// #include "../../dietlibc/x86_64/rand.h"
extern int syscall_table_rand[331];

void putnbr_new(int n)
{
  char c;

  if (n > 9)
    putnbr(n / 10);
  c = n % 10 + '0';
  __libc_write(1, &c, 1);
}

void
tracer(pid_t child_pid)
{
    int                     status;
    struct user_regs_struct regs;

    waitpid(child_pid, &status, 0);
    if (!WIFSTOPPED(status))
    {
        write("Incorrect state.\n", 2, 17);
        return;
    }
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_KILL);
    while (WIFSTOPPED(status))
    {
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);
        ptrace(12, child_pid, 0, &regs); // PTRACE_GETREGS

        short ax = syscall_table_rand[1];
        // write("\n", 1, 1);
        // write("Orig rax: ", 1, 10);
        // putnbr_new((int)regs.orig_rax);
        // write("\n", 1, 1);
        // write("Write syscall rand: ", 1, 21);
        // putnbr_new((long long unsigned int)ax);
        // write("\n", 1, 1);
        if (regs.orig_rax == (long long unsigned int)ax)
        {
            regs.orig_rax = 1;
            ptrace(13, child_pid, 0, &regs); // PTRACE_SETREGS
        }
    }
}
