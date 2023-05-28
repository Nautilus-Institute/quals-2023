#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/*
.text:000000000062BCCC                 int     3               ; Trap to Debugger
.text:000000000062BCCD                 push    10h
.text:000000000062BCCF                 pop     rcx
.text:000000000062BCD0                 lea     rsi, aDrmIoctlI915Ge+4 ; "IOCTL_I915_GETPARAM"
.text:000000000062BCD7                 rep movsb
.text:000000000062BCD9                 xor     eax, eax
.text:000000000062BCDB                 jmp     short loc_62BCF9
*/
const char patch[] = {
    0x90, 0x6A, 0x10, 0x59, 0x48, 0x8D, 0x35, 0xB9, 0x16, 0x26, 0x00, 0xF3, 0xA4, 0x31, 0xC0, 0xEB, 0x1C, 0xCC, 0xCC
};

char license[0x100] = { 0 };


int patch_qemu() {
    FILE* f = fopen("/usr/bin/qemu-aarch64-static", "r+");
    if (f == NULL) {
        puts("Could not find qemu");
        return -1;
    }

    fseek(f, 0x22bccc, SEEK_SET);
    fwrite(patch, sizeof(patch), 1, f);
    fseek(f, 0x48d390, SEEK_SET);
    fwrite(license, sizeof(license), 1, f);

    fclose(f);
    return 0;
}

void remove_index(char** a, unsigned int i) {
    char* n = NULL;
    do {
        n = a[i+1];
        a[i++] = n;
    } while(n != NULL);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        puts("./init_drm <program> <-l license> [options]");
        return -1;
    }

    int found_license = 0;
    for (unsigned int i=1; argv[i]; i++) {
        if (strcmp("-l",argv[i]))
            continue;
        remove_index(argv, i); //remove -l

        if (argv[i] == NULL) {
            break;
        }
        char* lname = argv[i];
        FILE* l = fopen(lname,"r");
        if (l == NULL) {
            puts("Could not read license file");
            return -1;
        }
        fread(license, 0x10, 1, l);
        fclose(l);
        printf("Loading with license %s\n",lname);
        remove_index(argv, i); // Remove file name
        found_license = 1;
        break;
    }

    if (!found_license) {
        puts("Missing license file");
        return -1;
    }

    if (patch_qemu() != 0) {
        return -1;
    }

    setuid(65534);
    seteuid(65534);
    setgid(65534);
    setegid(65534);

    argv[0] = "/usr/bin/qemu-aarch64-static";
    execv(argv[0], argv);
}
