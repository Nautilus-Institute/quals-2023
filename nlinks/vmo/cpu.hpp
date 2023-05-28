#ifndef _CPU_H
#define _CPU_H

#include <stdint.h>
#include <exception>
#include <vector>

#include "vm.hpp"
#include "instr.hpp"


#define EXTRACT_OP0 \
    switch (this->instr->op0_type) { \
		case OPT_REG: \
			op0 = this->get_reg(this->instr->op0 >> 8, this->instr->op0 & 0xff); \
			break; \
		case OPT_IMM: \
			op0 = this->instr->op0; \
			break; \
		default: \
			this->halt(true); \
			break; \
	} \
    if (this->halted()) { \
		return; \
	}

#define EXTRACT_OP1 \
    switch (this->instr->op1_type) { \
		case OPT_REG: \
			op1 = this->get_reg(this->instr->op1 >> 8, this->instr->op1 & 0xff); \
			break; \
		case OPT_IMM: \
			op1 = this->instr->op1; \
			break; \
        case OPT_MEMREG: \
            { \
                uint8_t mem_size = this->instr->op1 & 0xff; \
                uint64_t reg_val = this->get_reg(this->instr->op1 >> 8, 8); \
                switch (mem_size) { \
                case 8: \
                    op1 = this->get_data64(reg_val); \
                    break; \
                case 4: \
                    op1 = this->get_data32(reg_val); \
                    break; \
                case 2: \
                    op1 = this->get_data16(reg_val); \
                    break; \
                case 1: \
                    op1 = this->get_data8(reg_val); \
                    break; \
                default: \
                    break; \
                } \
            } \
            break; \
		default: \
			this->halt(true); \
			break; \
	} \
    if (this->halted()) { \
		return; \
	}

#define EXTRACT_OP2 \
	switch (this->instr->op2_type) { \
		case OPT_REG: \
			op2 = this->get_reg(this->instr->op2 >> 8, this->instr->op2 & 0xff); \
			break; \
		case OPT_IMM: \
			op2 = this->instr->op2; \
			break; \
        case OPT_MEMREG: \
            { \
                uint8_t mem_size = this->instr->op2 & 0xff; \
                uint64_t reg_val = this->get_reg(this->instr->op2 >> 8, 8); \
                switch (mem_size) { \
                case 8: \
                    op2 = this->get_data64(reg_val); \
                    break; \
                case 4: \
                    op2 = this->get_data32(reg_val); \
                    break; \
                case 2: \
                    op2 = this->get_data16(reg_val); \
                    break; \
                case 1: \
                    op2 = this->get_data8(reg_val); \
                    break; \
                default: \
                    break; \
                } \
            } \
            break; \
		default: \
			this->halt(true); \
			break; \
	} \
	if (this->halted()) { \
		return; \
	}

#define SET_OP0 \
    switch (this->instr->op0_type) { \
		case OPT_REG: \
			this->set_reg(this->instr->op0 >> 8, this->instr->op0 & 0xff, op0); \
			break; \
        case OPT_MEM: \
            switch (this->instr->op0 & 0xff) { \
                case 8: \
                    this->put_data64(this->instr->op0 >> 8, op0); \
                    break; \
                case 4: \
                    this->put_data32(this->instr->op0 >> 8, op0); \
                    break; \
                case 2: \
                    this->put_data16(this->instr->op0 >> 8, op0); \
                    break; \
                case 1: \
                    this->put_data8(this->instr->op0 >> 8, op0); \
                    break; \
                default: \
                    break; \
            } \
            break; \
        case OPT_MEMREG: \
            { \
                uint8_t mem_size = this->instr->op0 & 0xff; \
                uint64_t reg_val = this->get_reg(this->instr->op0 >> 8, 8); \
                switch (mem_size) { \
                case 8: \
                    this->put_data64(reg_val, op0); \
                    break; \
                case 4: \
                    this->put_data32(reg_val, op0); \
                    break; \
                case 2: \
                    this->put_data16(reg_val, op0); \
                    break; \
                case 1: \
                    this->put_data8(reg_val, op0); \
                    break; \
                default: \
                    break; \
                } \
            } \
            break; \
		default: \
			this->halt(true); \
			break; \
	}


enum reg64_t { RAX, RCX, RDX, RBX, RSI, RDI, RSP, RBP, R8, R9, R10, R11, R12, R13, R14, R15, T0, T1, T2, RIP, REGS_COUNT };

union Register {
    uint64_t reg64;
	uint32_t reg32;
	uint16_t reg16;
	struct {
		uint8_t reg8_l;
		uint8_t reg8_h;
	};
};

class CPU {
private:
    Register registers[REGS_COUNT];
    bool b_halted;
    InstrData *instr;
    VM* m_vm;
    std::vector<uint64_t> stack;
    int m_addMess;
    int m_subMess;
    int m_xorMess;
public:
    CPU(VM* vm);

    uint64_t get_ip(void) const { return registers[RIP].reg64; };
    uint64_t get_reg(enum reg64_t n) const { if (n < REGS_COUNT) return registers[n].reg64; else throw std::exception(); };
    uint64_t get_reg(int offset, int size);
    void set_ip(uint64_t v) { registers[RIP].reg64 = v; };
    void set_reg(enum reg64_t n, uint64_t v) { if (n < REGS_COUNT) registers[n].reg64 = v; else throw std::exception(); };
    void set_reg(int offset, int size, uint64_t v);
    uint64_t update_ip(int32_t v) { return registers[RIP].reg64 += v; };
    uint64_t update_reg(enum reg64_t n, int64_t v) { if (n < REGS_COUNT) return registers[n].reg64 += v; else throw std::exception(); };
    uint64_t update_reg(int offset, int size, int64_t v);
    bool halted(void) const { return b_halted; };
    void halt(bool h) { b_halted = h; };;

    uint8_t get_code8() { return get_data8(get_ip()); };
    uint16_t get_code16() { return get_data16(get_ip()); };
    uint32_t get_code32() { return get_data32(get_ip()); };
    uint64_t get_code64() { return get_data64(get_ip()); };

    bool exec(InstrData* instr);

    uint64_t pop64() { if (stack.size() == 0) { return 0; } uint64_t v = stack.back(); stack.pop_back(); return v;}
    void push64(uint32_t v) { stack.push_back(v); }
    uint64_t get_data64(uint64_t addr);
    void put_data64(uint64_t addr, uint64_t v);
    uint32_t get_data32(uint64_t addr);
    void put_data32(uint64_t addr, uint32_t v);
    uint16_t get_data16(uint64_t addr);
    void put_data16(uint64_t addr, uint16_t v);
    uint8_t get_data8(uint64_t addr);
    void put_data8(uint64_t addr, uint8_t v);

    // Instruction handlers
    void add();
    void sub();
    void xor_();
    void sal();
    void and_();
    void or_();

    void jmp();
    void je();
    void jne();
    void ja();
    void jae();
    void jb();
    void jbe();
    void jg();
    void jge();
    void jl();
    void jle();
    void call();
    void ret();

    void lea();
    void mov();

    // angr-killers
    // You can't simply skip them; Skipping will result in incorrect
    // computation results in other instruction handlers.
    void ak0();
    void ak1();
    void ak2();
    void ak3();
};

#endif
