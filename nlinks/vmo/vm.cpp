#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <fstream>

#include "vm.hpp"
#include "cpu.hpp"
#include "parser.hpp"

#define FLAG_PATH "./flag"


VM::VM()
    : curr_proc_id(0), players(0)
{
    memset(arena, 0xcc, CORE_SIZE);
}


int load_program(VM* vm, uint8_t* program, size_t program_size)
{
    // Calculate start position
    int start_pos = 0;
#ifdef DEBUG
    fprintf(stderr, "start_pos: %#x, size: %d\n", start_pos, program_size);
#endif
    memcpy(vm->arena + start_pos, program, program_size);
    return start_pos;
}


int run(VM* vm)
{
    CPU* cpu = new CPU(vm);
    Parser parser;

    for (int i = 0; i < MAX_CYCLE; ++i) {
#ifdef DEBUG
        fprintf(stderr, "[%#08x (%d)]\n", cpu->get_ip(), i);
#endif
        InstrData instr;
        parser.parse(vm, cpu, &instr);
        cpu->exec(&instr);
#ifdef DEBUG
        fprintf(stderr, "  rax=%llx, rdx=%llx\n", cpu->get_reg(RAX), cpu->get_reg(RDX));
        fprintf(stderr, "  rsp=%llx, rbp=%llx\n", cpu->get_reg(RSP), cpu->get_reg(RBP));
#endif
        if (cpu->halted()) {
            // The process is dead
#ifdef DEBUG
            fprintf(stderr, "Halted\n");
#endif
            break;
        }
    }
    return 0;
}

#ifdef STANDALONE
int main(int argc, char** argv)
{
    VM* vm = new VM;

    if (argc < 1) {
        std::cerr << "Insufficient number of arguments" << std::endl;
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t buf[file_size];
    if (fread(buf, 1, file_size, fp) != file_size) {
        perror("fread");
        return 1;
    }
    fclose(fp);

    load_program(vm, buf, file_size);

    run(vm);
}
#else
extern "C" void run_code(uint8_t* code, uint64_t size)
{
    VM* vm = new VM;
    load_program(vm, code, size);
    run(vm);
    delete vm;
}

void tea_core(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i=ADD0(i,1)) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt(const uint32_t key[4], uint8_t* data, uint64_t size)
{
    for (int i = 0; i < size; i = ADD1(i, 8)) {
        tea_core((uint32_t*)(data + i), key);
    }
}

extern "C" void decrypt_and_run_code(uint8_t* code, uint64_t size)
{
    uint32_t key[4];
    uint8_t *decrypted_code = (uint8_t*)malloc((size + 7) / 8 * 8);
    memcpy(decrypted_code, code, size);
    printf("Passphrase:\n");
    read(0, &key[0], 4);
    read(0, &key[1], 4);
    key[2] = 0x13371338;
    key[3] = 0x1339133a;
    decrypt(key, decrypted_code, size);

    run_code(decrypted_code, size);
    free(decrypted_code);
}
#endif
