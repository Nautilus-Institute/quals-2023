#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <elf.h>
#include <sys/stat.h>
#include "sha256.c"

#define VERIFY 1
#define DEBUG 0

#define ALARM_SECONDS 50

#if DEBUG
#define dprintf printf
#else
#define dprintf(...) ;
#endif

#define SHA256_HEX_LEN (SHA256_BLOCK_SIZE*2)

void fail() {
    puts("VERIFICATION FAILED");
    fflush(stdout);
    exit(1);
    abort();
    while(1){};
}


uint8_t from_hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = c | 0x20;
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    puts("Error: Non hex character in hash");
    fail();
    return 0;
}

uint8_t from_hex_byte(char* hex) {
    uint8_t byte = from_hex_nibble(hex[0]) << 4;
    byte |= from_hex_nibble(hex[1]);
    return byte;
}

char to_hex_nibble(uint8_t c) {
    if (c < 10) {
        return '0' + c;
    }
    return 'A'+(c-10);
}

void to_hex_byte(char* hex, uint8_t v) {
    hex[0] = to_hex_nibble((v&0xf0) >> 4);
    hex[1] = to_hex_nibble(v&0xf);
}

__attribute__((noinline)) char* hash_to_hex(uint8_t* hash) {
    char* hex = calloc(SHA256_HEX_LEN+8, 1);
    assert(hex);
    for (size_t i=0; i/2<SHA256_BLOCK_SIZE && i+1<SHA256_HEX_LEN; i+=2) {
        uint8_t v = hash[i/2];
        to_hex_byte(&hex[i], v);
    }
    return hex;
}

#if VERIFY
#else
size_t hash_num = 0;
#endif

char* get_salt(char* salt, FILE* f, int indx) {
    const size_t len = 0x100;
    char* out = calloc(len+64, 1);
    size_t salt_off = strlen(salt);
    strncpy(out, salt, len);

#if VERIFY
    int c = fgetc(f);
    if (c != '\n' && c != EOF) {
        ungetc(c, f);
    }

    while(salt_off < len/2) {
        char c = 0;
        size_t nr = fread(&c, 1, 1, f);
        if (nr != 1) {
            puts("Error: Missing hash index (hashes must be in index:hash form)");
            fail();
        }
        if (c == ':')
            break;
        out[salt_off++] = c;
    }
#else
    char hash_num_str[32] = {0};
    sprintf(hash_num_str, "%lu", hash_num++);
    strcat(out, hash_num_str);
    salt_off += strlen(hash_num_str);

    fprintf(f, "%s:", hash_num_str);
#endif

    to_hex_byte(&out[salt_off], indx);

    dprintf("Salt is `%s`\n", out);

    return out;
}

__attribute__((noinline)) uint8_t* read_next_hash(FILE* f) {
    char* hex = calloc(SHA256_HEX_LEN+32, 1);
    assert(hex);


    size_t nr = fread(hex, 1, SHA256_HEX_LEN, f);
    if (nr != SHA256_HEX_LEN) {
        puts("Error: Missing hashes, hash file truncated?");
        fail();
    }

    dprintf("Read in hash %s\n", hex);

    uint8_t* out = calloc(SHA256_BLOCK_SIZE+8, 1);
    assert(out);

    for (size_t i=0; i+1<SHA256_HEX_LEN && (i/2)<SHA256_BLOCK_SIZE; i+=2) {
        uint8_t byte = from_hex_byte(&hex[i]);
        out[i/2] = byte;
    }
    free(hex);
    return out;
}

__attribute__((noinline)) uint8_t compare_hashes(uint8_t* a, uint8_t* b, int dofail) {
    uint8_t good = 1;
    for (size_t i=0; i<SHA256_BLOCK_SIZE; i++) {
        if (a[i] != b[i])
            good &= 0;
        else
            good &= 1;
    }
    if (!good) {
        puts("Error: Provided hash is invalid");
        if (dofail) {
            fail();
        }
    }
    return good;
}

#define KEY_LEN 30

uint8_t* key_data = NULL;
uint8_t* hash_buff = NULL;

void do_seek(FILE* f, size_t off) {
    if (fseek(f, off, SEEK_SET) != 0) {
        puts("Error: Unable to seek to offset in binary");
        fail();
    }
}

size_t fread_or_fail(void* ptr, size_t s, size_t n, FILE* f) {
    dprintf("Reading %lu entries of size %lu\n", n, s);
    size_t nr = fread(ptr, s, n, f);
    if (nr != n) {
        puts("Error: Unable to read all of required data from file");
        fail();
    }
    return nr;
}

#define HASH_BUFF_SIZE 4096
__attribute__((noinline)) uint8_t* hash_from_file(FILE* f, size_t off, size_t len, char* salt) {
    if (hash_buff == NULL)
        hash_buff = calloc(HASH_BUFF_SIZE+8, 1);
    assert(hash_buff);

    if (key_data == NULL) {
        puts("Error: No key loaded");
        fail();
    }

    do_seek(f, off);


    SHA256_CTX ctx = {0};
    sha256_init(&ctx);
    if (salt != NULL) {
        sha256_update(&ctx, (uint8_t*)salt, strlen(salt));
    }

    sha256_update(&ctx, key_data, KEY_LEN);

    size_t left = len;
    while (left != 0) {
        size_t to_read = left;
        if (to_read > HASH_BUFF_SIZE)
            to_read = HASH_BUFF_SIZE;

        size_t nr = fread_or_fail(hash_buff, 1, to_read, f);
        if (nr != to_read) {
            puts("Error: Could not read all data from file");
            fail();
        }
        sha256_update(&ctx, hash_buff, nr);

        assert(nr <= left);
        left -= nr;
    }

    uint8_t* out = calloc(SHA256_BLOCK_SIZE, 1);
    assert(out);

    sha256_final(&ctx, out);
    return out;
}


int check_next_hash(uint8_t* hash, FILE* f, int dofail) {
#if VERIFY
    uint8_t* next = read_next_hash(f);
    assert(next);
    if (!compare_hashes(hash, next, dofail)) {
        printf("Invalid hash: %s\n", hash_to_hex(next));
        fail();
        return 0;
    }
#else
    char* d = hash_to_hex(hash);
    fwrite(d,1,strlen(d), f);
    free(d);
    fwrite("\n",1,1,f);
#endif
    return 1;
}

void verify_binary(FILE* f, FILE* hf) {
    const size_t hdr_len = sizeof(Elf64_Ehdr);

    Elf64_Ehdr* hdr = calloc(hdr_len+8, 1);
    assert(hdr);

    uint8_t* hdr_hash = hash_from_file(f, 0, hdr_len, get_salt("elf", hf, 0));
    dprintf("Elf Header hash = %s\n", hash_to_hex(hdr_hash));
    if (!check_next_hash(hdr_hash, hf, 1)) {
        fail();
    }

    do_seek(f, 0);

    fread_or_fail(hdr, hdr_len, 1, f);

    if (hdr->e_ident[EI_MAG0] != ELFMAG0
        || hdr->e_ident[EI_MAG1] != ELFMAG1
        || hdr->e_ident[EI_MAG2] != ELFMAG2
        || hdr->e_ident[EI_MAG3] != ELFMAG3) {
        puts("Error: Not an elf");
        fail();
    }
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        puts("Error: Only 64bit allowed");
        fail();
    }
    if (hdr->e_ehsize != hdr_len) {
        puts("Error: Bad header size");
        fail();
    }

    Elf64_Phdr* phdr;

    if (hdr->e_phentsize != sizeof(Elf64_Phdr) || hdr->e_phnum > PN_XNUM) {
        puts("Error: Bad header size");
        fail();
    }

    const size_t phdr_len = sizeof(Elf64_Phdr) * hdr->e_phnum;

    uint8_t* phdr_hash = hash_from_file(f, hdr->e_phoff, phdr_len, get_salt("phdrs", hf, 0));
    dprintf("Elf Progam Header hash = %s\n", hash_to_hex(phdr_hash));
    if (!check_next_hash(phdr_hash, hf, 1)) {
        fail();
    }


    if (hdr->e_shentsize != sizeof(Elf64_Shdr) || hdr->e_shnum > SHN_LORESERVE) {
        puts("Error: Bad header size");
        fail();
    }

    const size_t shdr_len = sizeof(Elf64_Shdr) * hdr->e_shnum;

    uint8_t* shdr_hash = hash_from_file(f, hdr->e_shoff, shdr_len, get_salt("shdrs", hf, 0));

    dprintf("Elf Section Header hash = %s\n", hash_to_hex(shdr_hash));
    if (!check_next_hash(shdr_hash, hf, 1)) {
        fail();
    }

    Elf64_Shdr* shdr = calloc(hdr->e_shnum+1, sizeof(Elf64_Shdr));
    do_seek(f, hdr->e_shoff);
    fread_or_fail(shdr, sizeof(Elf64_Shdr), hdr->e_shnum, f);

    for (size_t i=0; i<hdr->e_shnum; i++) {
        size_t start = shdr[i].sh_offset;
        size_t size = shdr[i].sh_size;
        if (shdr[i].sh_type == SHT_NOBITS) {

        } else if (i+1 < hdr->e_shnum) {
            size_t nsize = shdr[i+1].sh_offset - start;
            //printf("(%lx) %lx vs %lx\n", shdr[i+1].sh_offset, size, nsize);
            assert(nsize >= size);
            size = nsize;
        }
        dprintf("Checking section header 0x%0lx (%lx+%lx->%lx)\n",
            i, start, size, start+size);
        uint8_t* sec_hash = hash_from_file(f, start, size, get_salt("s", hf, i));
        dprintf("Section 0x%02lx hash = %s\n", i, hash_to_hex(sec_hash));
        if (!check_next_hash(sec_hash, hf,0)) {
            //printf("Failed to verify section #%lu\n", i);
            fail();
        }
    }
}

void load_key(FILE* f) {
    key_data = calloc(KEY_LEN+32,1);
    assert(key_data);
    size_t nr = fread(key_data, 1, KEY_LEN, f);
    if (nr != KEY_LEN) {
        puts("Error: Unable to read all of key");
        fail();
    }
}

char* save_hashes() {
    char buf[64] = {0};
    puts("Enter number of hashes (max 48)");
    fgets(buf, 32, stdin);
    uint16_t num_hashes = atoi(buf);
    if (num_hashes> 48) {
        puts("Too many hashes! Take it easy");
        exit(0);
        abort();
        return NULL;
    }

    char tmp_name[32] = {0};
    strncpy(tmp_name, "/tmp/hashXXXXXX", 32);
    int hash_fd = mkstemp(tmp_name);
    FILE* f = fdopen(hash_fd, "w");
    char* hash_path = strdup(tmp_name);

    puts("Send your hashes (index:hash)");

    char* data = calloc(0x1000,1);
    for (size_t i=0; i<num_hashes; i++) {
        char c = 0;
        for (size_t j=0; j<32 && c != ':'; j++) {
            if (fread(&c, 1, 1, stdin) != 1) {
                puts("Could not read hash index before `:`");
                exit(0);
                abort();
            }
            //printf("`%c`\n", c);
            fwrite(&c, 1, 1, f);
        };
        if (!fgets(data, SHA256_HEX_LEN+2, stdin)) {
            printf("Could not read hash #%lu", i);
            exit(0);
            abort();
            return NULL;
        }
        data[SHA256_HEX_LEN] = 0;
        //printf("'%s'\n", data);
        fputs(data, f);
    }
    fclose(f);
    free(data);
    return hash_path;
}

char* save_binary() {
    char buf[64] = {0};
    puts("Enter size of binary (max 16384)");
    fgets(buf, 32, stdin);
    uint16_t bin_len = atoi(buf);
    if (bin_len < 32 || bin_len > 0x4000) {
        puts("Bad Size!");
        exit(0);
        abort();
        return NULL;
    }

    char tmp_name[32] = {0};
    strncpy(tmp_name, "/tmp/binXXXXXX", 32);
    int bin_fd = mkstemp(tmp_name);
    FILE* f = fdopen(bin_fd, "w");
    char* bin_path = strdup(tmp_name);

    puts("Send me the goods:");

    uint8_t* data = calloc(0x2000,1);
    size_t amt_read = 0;
    while (amt_read < bin_len) {
        size_t left = bin_len - amt_read;
        size_t to_read = 0x1000;
        if (left < 0x1000) {
            to_read = left;
        }
        //printf("reading in %x\n", to_read);
        size_t n_read = fread(data, 1, to_read, stdin);
        //printf("read in %x\n", n_read);
        if (n_read == 0) {
            puts("Unable to read all bytes :(");
            exit(0);
            abort();
            return NULL;
        }

        fwrite(data, 1, n_read, f);
        amt_read += n_read;
    }
    fclose(f);
    chmod(bin_path, 0777);
    free(data);
    return bin_path;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        puts("./verify <key> [binary] [hashes]");
        exit(1);
    }

    char* bin_path = NULL;
    if (argc < 3) {
        bin_path = save_binary();
    } else {
        bin_path = strdup(argv[2]);
    }

    FILE* bin = fopen(bin_path, "r");
    if (bin == NULL) {
        printf("Unable to open binary %s\n", bin_path);
        fail();
    }

    char* hash_path = NULL;
    if (argc < 4) {
        hash_path = save_hashes();
    } else {
        hash_path = strdup(argv[3]);
    }

#if VERIFY
    FILE* hashes = fopen(hash_path, "r");
#else
    FILE* hashes = fopen(hash_path, "w");
#endif
    if (hashes == NULL) {
        printf("Unable to open hashes %s\n", hash_path);
        fail();
    }

    FILE* key = fopen(argv[1], "r");
    if (hashes == NULL) {
        printf("Unable to open key %s\n", argv[1]);
        fail();
    }

    load_key(key);
    fclose(key);

    puts("Verifying binary...");
    verify_binary(bin, hashes);

#if VERIFY
#else
#endif
    fclose(bin);
    fclose(hashes);

    char* args[] = {bin_path, NULL};
    puts("Successfully verified binary!");
    execve(bin_path, args, NULL);
}
