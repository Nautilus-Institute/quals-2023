#ifndef FUCKUP_H
#define FUCKUP_H

#include <x86_64-linux-gnu/asm/unistd_32.h>

void send_string(char *msg);
unsigned int my_syscall(int eax, int ebx, int ecx, int edx, int esi, int edi, int ebp);
void RandomizeApp();
void ConvertValToHex(unsigned int Val, char *Buffer);

#define PROT_READ     0x01
#define PROT_WRITE    0x02
#define PROT_EXEC     0x04
#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20

#define PAGE_SIZE 4096

#define f_mmap(addr, len, prot, flags, fd, offset) my_syscall(__NR_mmap2, (int)addr, len, prot, flags, (int)fd, (int)offset)
#define f_mprotect(addr, len, prot) my_syscall(__NR_mprotect, (int)addr, len, prot, 0, 0, 0)
#define f_munmap(addr, len) my_syscall(__NR_munmap, (int)addr, len, 0, 0, 0, 0)
#define f_read(fd, buffer, len) my_syscall(__NR_read, fd, (int)buffer, len, 0, 0, 0)
#define f_write(fd, buffer, len) my_syscall(__NR_write, fd, (int)buffer, len, 0, 0, 0)
#define f_getrandom(buffer, len, flags) my_syscall(__NR_getrandom, (int)buffer, len, flags, 0, 0, 0)
#define f_exit(code) my_syscall(__NR_exit, code, 0, 0, 0, 0, 0)

#define R 16
typedef struct WELLStruct
{
    unsigned int state_i;
    unsigned int STATE[R];
} WELLStruct;

void InitWELLRNG512a (WELLStruct *ctx);
double WELLRNG512a (WELLStruct *ctx);
//void PrintWELL();

#endif