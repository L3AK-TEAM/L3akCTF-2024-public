#include "main.h"

bool
program_start2(void)
{
    pid_t child_pid = fork();

    if (child_pid < 0)
    {
        write("Fork failed.\n", 2, 13);
        return (true);
    }
    if (child_pid == 0)
        tracee();
    else
        tracer(child_pid);
    return (false);
}

bool
program_start(void)
{
    pid_t child_pid = fork();

    if (child_pid < 0)
    {
        write("Fork failed.\n", 2, 13);
        return (true);
    }
    if (child_pid == 0)
        program_start2();
    else
        tracer(child_pid);
    return (false);
}

int
main(void)
{
    write("Sadly you won't see this message!\n", 1, 34);
    if (program_start() == true)
        return (1);
    return 0;
}
