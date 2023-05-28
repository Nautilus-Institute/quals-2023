#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "seccomp-bpf.h"

#define PAGE_ALIGN(x) (((x + 0xfff) / 0x1000) * 0x1000)

// gcc -o launcher main.c -static

typedef struct {
    unsigned long long start;
    size_t len;
} region_t;

int install_seccomp_filter()
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(munmap),
        KILL_PROCESS
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        goto failed;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        goto failed;
    }

    return 0;
failed:
    return 1;
}

int collect_regions(region_t *regions, size_t n)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL)
    {
        perror("open maps");
        return 1;
    }

    unsigned long long start, end;
    char permissions[5];
    char filename[256];
    size_t region_cnt = 0;
    while (fscanf(fp, "%llx-%llx %4s %*llx %*x:%*x %*u",
                    &start, &end, permissions) == 3)
    {
        int c;
        int i = 0;
        while ((c = fgetc(fp)) != '\n') {
            if ((c == '/' || c == '[') && i < 255)
            {
                // Filename found, start reading it
                filename[i++] = c;
                while ((c = fgetc(fp)) != '\n')
                {
                    if (c == '\0')
                        break;
                    if (i < 255)
                        filename[i++] = c;
                }
                break;
            }
        }

        if (!strncmp(filename, "[heap]", 6))
        {
            break;
        }

        regions[region_cnt].start = start;
        regions[region_cnt].len = end - start;
        region_cnt++;

        if (region_cnt >= n) break;
        memset(filename, 0, sizeof(filename));
    }

    fclose(fp);

    return region_cnt;
}

void hollow_and_jump(region_t *regions, size_t region_cnt, void *ptr)
{
    int i = 0;
    for (i = 0; i < region_cnt; i++) {
        int result = 0;
        asm volatile (
            "syscall"
            :
            : "a" (11), "D" (regions[i].start), "S" (regions[i].len)
            : "rcx", "r11", "memory"
            );
    }
    ((void (*)(void))ptr)();
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Need image file\n");
        return 1;
    }

    char *sfm_fd_env = getenv("SFM_FD");
    if (sfm_fd_env == NULL)
    {
        fprintf(stderr, "No fd provided\n");
        return 1;
    }

    int sfm_fd = atoi(sfm_fd_env);
    if (dup2(sfm_fd, 3) < 0)
    {
        perror("correcting file descriptors");
        return 1;
    }

    char *image_path = argv[1];

    int fd = open(image_path, O_RDONLY);
    if (fd < 0)
    {
        perror("open image file");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        perror("stat image file");
        close(fd);
        return 1;
    }

    size_t aligned_len = PAGE_ALIGN(st.st_size);
    void *ptr = mmap(NULL, aligned_len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED)
    {
        perror("map region");
        close(fd);
        return 1;
    }

    if (read(fd, ptr, st.st_size) < st.st_size)
    {
        perror("read image content");
        close(fd);
        return 1;
    }

    //if (mprotect(ptr, aligned_len, PROT_READ|PROT_WRITE|PROT_EXEC)) {
    if (mprotect(ptr, aligned_len, PROT_READ|PROT_EXEC)) {
        perror("mprotect region");
        close(fd);
        return 1;
    }

    // hollow out process
    region_t regions[20] = {0};
    size_t region_cnt = collect_regions(regions, 20);
    if (!region_cnt) {
        perror("region collection");
        close(fd);
        return 1;
    }

    // close fds
    if (close(0) || close(1) || close(2) || close(fd) || close(sfm_fd)) {
        perror("closing std streams");
        return 1;
    }

    void *hollow_logic_ptr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (hollow_logic_ptr == MAP_FAILED)
    {
        perror("map hollow logic region");
        return 1;
    }

    memcpy(hollow_logic_ptr, hollow_and_jump, 0x80);

    if (mprotect(hollow_logic_ptr, 0x1000, PROT_READ|PROT_EXEC))
    {
        perror("mprotect hollow logic region");
        return 1;
    }

    if (install_seccomp_filter() != 0)
    {
        fprintf(stderr, "Failed to isntall seccomp filter\n");
        return 1;
    }


    ((void (*)(region_t *, size_t, void *))hollow_logic_ptr)(regions, region_cnt, ptr);
}
