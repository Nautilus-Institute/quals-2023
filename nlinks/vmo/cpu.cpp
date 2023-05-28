#include <string.h>
#include <iostream>
#include <unistd.h>
#include <stdexcept>
#include "cpu.hpp"

using namespace std;


CPU::CPU(VM* vm)
    : m_vm(vm), b_halted(false), m_addMess(15), m_subMess(18), m_xorMess(22)
{
	set_ip(0);
	set_reg(RSP, CORE_SIZE - 8);
}


//
// Memory accessing
//

uint64_t CPU::get_reg(int offset, int size)
{
	int reg_num = offset / 8, in_reg_offset = offset % 8;
	if ((reg64_t)reg_num < REGS_COUNT)  {
		reg64_t reg = (reg64_t)reg_num;
		switch (size) {
			case 8:
				return registers[reg].reg64;
			case 4:
				return registers[reg].reg32;
			case 2:
				return registers[reg].reg16;
			case 1:
				if (in_reg_offset == 0) {
					return registers[reg].reg8_l;
				}
				else {
					return registers[reg].reg8_h;
				}
			default:
				halt(true);
		}
		
	 }
	 else {
		 throw std::exception();
	 }
	 return 0;
}

void CPU::set_reg(int offset, int size, uint64_t v)
{
	int reg_num = offset / 8, in_reg_offset = offset % 8;
	if ((reg64_t)reg_num < REGS_COUNT)  {
		reg64_t reg = (reg64_t)reg_num;
		switch (size) {
			case 8:
				registers[reg].reg64 = v;
				break;
			case 4:
				registers[reg].reg32 = (uint32_t)v;
				break;
			case 2:
				registers[reg].reg16 = (uint16_t)v;
				break;
			case 1:
				if (in_reg_offset == 0) {
					registers[reg].reg8_l = (uint8_t)v;
				}
				else {
					registers[reg].reg8_h = (uint8_t)v;
				}
				break;
			default:
				halt(true);
				break;
		}
		
	 }
	 else {
		 throw std::exception();
	 }
}

uint64_t CPU::update_reg(int offset, int size, int64_t v)
{
	int reg_num = offset / 8, in_reg_offset = offset % 8;
	if ((reg64_t)reg_num < REGS_COUNT)  {
		reg64_t reg = (reg64_t)reg_num;
		switch (size) {
			case 8:
				registers[reg].reg64 += v;
				return registers[reg].reg64;
			case 4:
				registers[reg].reg32 += (int32_t)v;
				return registers[reg].reg32;
			case 2:
				registers[reg].reg16 += (int16_t)v;
				return registers[reg].reg16;
			case 1:
				if (in_reg_offset == 0) {
					registers[reg].reg8_l += (int8_t)v;
					return registers[reg].reg8_l;
				}
				else {
					registers[reg].reg8_h += (int8_t)v;
					return registers[reg].reg8_h;
				}
			default:
				halt(true);
		}
		
	 }
	 else {
		 throw std::exception();
	 }
	 return 0;
}

uint64_t CPU::get_data64(uint64_t addr)
{
    uint8_t data[8] = {0};
    data[0] = *(uint32_t*)&m_vm->arena[addr % CORE_SIZE];
    data[1] = *(uint32_t*)&m_vm->arena[(addr + 1) % CORE_SIZE];
    data[2] = *(uint32_t*)&m_vm->arena[(addr + 2) % CORE_SIZE];
    data[3] = *(uint32_t*)&m_vm->arena[(addr + 3) % CORE_SIZE];
	data[4] = *(uint32_t*)&m_vm->arena[(addr + 4) % CORE_SIZE];
    data[5] = *(uint32_t*)&m_vm->arena[(addr + 5) % CORE_SIZE];
    data[6] = *(uint32_t*)&m_vm->arena[(addr + 6) % CORE_SIZE];
    data[7] = *(uint32_t*)&m_vm->arena[(addr + 7) % CORE_SIZE];
    return *(uint64_t*)data;
}

uint32_t CPU::get_data32(uint64_t addr)
{
    uint8_t data[4] = {0};
    data[0] = *(uint32_t*)&m_vm->arena[addr % CORE_SIZE];
    data[1] = *(uint32_t*)&m_vm->arena[(addr + 1) % CORE_SIZE];
    data[2] = *(uint32_t*)&m_vm->arena[(addr + 2) % CORE_SIZE];
    data[3] = *(uint32_t*)&m_vm->arena[(addr + 3) % CORE_SIZE];
    return *(uint32_t*)data;
}

uint16_t CPU::get_data16(uint64_t addr)
{
    uint8_t data[2] = {0};
    data[0] = *(uint32_t*)&m_vm->arena[addr % CORE_SIZE];
    data[1] = *(uint32_t*)&m_vm->arena[(addr + 1) % CORE_SIZE];
    return *(uint16_t*)data;
}

uint8_t CPU::get_data8(uint64_t addr)
{
    return m_vm->arena[addr % CORE_SIZE];
}

void CPU::put_data64(uint64_t addr, uint64_t v)
{
    uint8_t data[8];
    *(uint64_t*)data = v;
    m_vm->arena[addr % CORE_SIZE] = data[0];
    m_vm->arena[(addr + 1) % CORE_SIZE] = data[1];
    m_vm->arena[(addr + 2) % CORE_SIZE] = data[2];
    m_vm->arena[(addr + 3) % CORE_SIZE] = data[3];
	m_vm->arena[(addr + 4) % CORE_SIZE] = data[4];
	m_vm->arena[(addr + 5) % CORE_SIZE] = data[5];
    m_vm->arena[(addr + 6) % CORE_SIZE] = data[6];
    m_vm->arena[(addr + 7) % CORE_SIZE] = data[7];
}

void CPU::put_data32(uint64_t addr, uint32_t v)
{
    uint8_t data[4];
    *(uint32_t*)data = v;
    m_vm->arena[addr % CORE_SIZE] = data[0];
    m_vm->arena[(addr + 1) % CORE_SIZE] = data[1];
    m_vm->arena[(addr + 2) % CORE_SIZE] = data[2];
    m_vm->arena[(addr + 3) % CORE_SIZE] = data[3];
}

void CPU::put_data16(uint64_t addr, uint16_t v)
{
    uint8_t data[2];
    *(uint16_t*)data = v;
    m_vm->arena[addr % CORE_SIZE] = data[0];
    m_vm->arena[(addr + 1) % CORE_SIZE] = data[1];
}

void CPU::put_data8(uint64_t addr, uint8_t v)
{
    m_vm->arena[addr % CORE_SIZE] = v;
}

//
// Execution
//

bool CPU::exec(InstrData* instr_)
{
    instr = instr_;
#ifdef DEBUG
	fprintf(stderr, "  opcode: %d\n", instr->opcode);
#endif
    switch (instr->opcode) {
	case OP_ADD:
#ifdef DEBUG
	fprintf(stderr, "  # add\n");
#endif
		add();
		break;
	case OP_SUB:
#ifdef DEBUG
	fprintf(stderr, "  # sub\n");
#endif
		sub();
		break;
	case OP_XOR:
#ifdef DEBUG
	fprintf(stderr, "  # xor\n");
#endif
		xor_();
		break;
	case OP_AND:
#ifdef DEBUG
	fprintf(stderr, "  # and\n");
#endif
		and_();
		break;
	case OP_OR:
#ifdef DEBUG
	fprintf(stderr, "  # or\n");
#endif
		or_();
		break;
	case OP_SAL:
#ifdef DEBUG
	fprintf(stderr, "  # sal\n");
#endif
		sal();
		break;
	case OP_JE:
#ifdef DEBUG
	fprintf(stderr, "  # je\n");
#endif
		je();
		break;
	case OP_JNE:
#ifdef DEBUG
	fprintf(stderr, "  # jne\n");
#endif
		jne();
		break;
	case OP_JA:
#ifdef DEBUG
	fprintf(stderr, "  # ja\n");
#endif
		ja();
		break;
	case OP_JG:
#ifdef DEBUG
	fprintf(stderr, "  # jg\n");
#endif
		jg();
		break;
	case OP_JMP:
#ifdef DEBUG
	fprintf(stderr, "  # jmp\n");
#endif
		jmp();
		break;
	case OP_CALL:
#ifdef DEBUG
	fprintf(stderr, "  # call\n");
#endif
		call();
		break;
	case OP_RET:
#ifdef DEBUG
	fprintf(stderr, "  # ret\n");
#endif
		ret();
		break;
	case OP_MOV:
#ifdef DEBUG
	fprintf(stderr, "  # mov\n");
#endif
		mov();
		break;
	case OP_AK0:
#ifdef DEBUG
	fprintf(stderr, "  # ak0\n");
#endif
		ak0();
		break;
	case OP_AK1:
#ifdef DEBUG
	fprintf(stderr, "  # ak1\n");
#endif
		ak1();
		break;
	case OP_AK2:
#ifdef DEBUG
	fprintf(stderr, "  # ak2\n");
#endif
		ak2();
		break;
	default:
		halt(true);
		break;
    }
    return true;
}

void CPU::add()
{
	uint64_t op1, op2, op0;

	try {
		EXTRACT_OP1
		EXTRACT_OP2

		if (m_addMess == 0) {
			throw runtime_error("0 div");
		}
		jmp(); // unreachable
	} catch (runtime_error& ex) {
		op0 = op1 + op2 + m_addMess;

		SET_OP0
	}

	update_ip(sizeof(InstrData));
}

void CPU::sub()
{
	uint64_t op1, op2, op0;

	try {
		EXTRACT_OP1
		EXTRACT_OP2

		if (m_subMess == 0) {
			throw runtime_error("0 div");
		}
		update_ip(sizeof(InstrData)); // unreachable
	} catch (runtime_error& ex) {
		op0 = op1 - op2 + m_subMess;

		SET_OP0
	}

	update_ip(sizeof(InstrData));
}

void CPU::xor_()
{
	uint64_t op1, op2, op0;

	try {
		EXTRACT_OP1
		EXTRACT_OP2

		if (m_xorMess == 0) {
			throw runtime_error("0 div");
		}
		op0 = 3; // unreachable
	} catch (runtime_error& ex) {
		op0 = op1 ^ op2;

		SET_OP0
	}

	update_ip(sizeof(InstrData));
}

void CPU::and_()
{
	uint64_t op1, op2, op0;

	EXTRACT_OP1
	EXTRACT_OP2

	op0 = op1 & op2;

	SET_OP0

	update_ip(sizeof(InstrData));
}

void CPU::or_()
{
	uint64_t op1, op2, op0;

	try {
		EXTRACT_OP1
		EXTRACT_OP2

		if (m_addMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		op0 = op1 | op2;

		SET_OP0
	}

	update_ip(sizeof(InstrData));
}

void CPU::sal()
{
	uint64_t op1, op2, op0;

	try {
		EXTRACT_OP1
		EXTRACT_OP2

		if (m_addMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		op0 = op1 << op2;

		SET_OP0
	}

	update_ip(sizeof(InstrData));
}

void CPU::mov()
{
	uint64_t op1, op0, op2 = 0;

	try {
		// value comes in from OP1. we don't use OP2
		EXTRACT_OP1
		EXTRACT_OP2
		if (op2 == 0) {
			throw runtime_error("0 div");
		}
		op0 = op1 / op2;
	} catch (runtime_error& ex) {
		// write out to the destination specified by OP0
		op0 = op1;
		SET_OP0
	}
	update_ip(sizeof(InstrData));
}

void CPU::call()
{
	uint64_t op0;
	try {
		if (m_addMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		// external function index comes in op0
		EXTRACT_OP0

		switch (op0) {
		case FUNC_READ:
			{
				int fd = get_reg(RDI);
				void* buf = &m_vm->arena[get_reg(RSI)];
				size_t count = get_reg(RDX);
	#ifdef DEBUG
				fprintf(stderr, "read %d %p %lld rsi = %llx\n", fd, buf, count, get_reg(RSI));
	#endif
				ssize_t r = read(fd, buf, count);
				set_reg(RAX, (uint64_t)r);
			}
			break;
		case FUNC_PRINTF:
			{
				char *fmt = (char*)&m_vm->arena[get_reg(RDI)];
				uint64_t n = get_reg(RSI);
				int r = printf(fmt, n);
				set_reg(RAX, (uint64_t)r);
			}
			break;
		default:
			halt(true);
			break;
		}

		// pop the return address
		update_reg(RSP, 8);
	}

	update_ip(sizeof(InstrData));
}

void CPU::ret()
{
	// TODO: Implement function ret. Skip for now
	halt(true);
}

void CPU::je()
{
	uint64_t op0 /* jump target */, op1, op2 = 0;

	try {
		EXTRACT_OP0
		EXTRACT_OP1

		if (m_xorMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		EXTRACT_OP2
	}

	if (op1 == op2) {
#ifdef DEBUG
		fprintf(stderr, "je - set_ip: %llx\n", op0);
#endif
		set_ip(op0);
	}
	else {
		update_ip(sizeof(InstrData));
	}
}

void CPU::jne()
{
	uint64_t op0 /* jump target */, op1, op2 = 0;

	try {
		EXTRACT_OP0
		EXTRACT_OP1

		if (m_xorMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		EXTRACT_OP2
	}

	if (op1 != op2) {
#ifdef DEBUG
		fprintf(stderr, "jne - set_ip: %llx\n", op0);
#endif
		set_ip(op0);
	}
	else {
		update_ip(sizeof(InstrData));
	}
}

void CPU::ja()
{
	uint64_t op0 /* jump target */, op1, op2 = 0;

	try {
		EXTRACT_OP0
		EXTRACT_OP1

		if (m_xorMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		EXTRACT_OP2
	}

	if (op1 > op2) {
#ifdef DEBUG
		fprintf(stderr, "ja - set_ip: %llx\n", op0);
#endif
		set_ip(op0);
	}
	else {
		update_ip(sizeof(InstrData));
	}
}

void CPU::jg()
{
	uint64_t op0 /* jump target */, op1, op2 = 0;

	try {
		EXTRACT_OP0
		EXTRACT_OP1

		if (m_xorMess == 0) {
			throw runtime_error("0 div");
		}
	} catch (runtime_error& ex) {
		EXTRACT_OP2
	}

	if ((int32_t)op1 > (int32_t)op2) {  // FIXME: Incorrect operand sizes
#ifdef DEBUG
		fprintf(stderr, "jg - set_ip: %llx\n", op0);
#endif
		set_ip(op0);
	}
	else {
		update_ip(sizeof(InstrData));
	}
}

void CPU::jmp()
{
	uint64_t op0 /* jump target */;

	EXTRACT_OP0

	set_ip(op0);
}

void CPU::ak0()
{
	uint8_t rand_buffer[4096];
	FILE* fp = fopen("/dev/urandom", "rb");
	if (fp == NULL) {
		_exit(1);
	}
	for (int i = 0; i < sizeof(rand_buffer); ++i) {
		fread(&rand_buffer[i], 1, 1, fp);
		try {
			if ((rand_buffer[i] & 0x20) != 0) {
				throw runtime_error("unexpected bit");
			}
		} catch (runtime_error& ex) {
			m_addMess = -1;
		}
	}
	fclose(fp);
	m_addMess++;
	update_ip(sizeof(InstrData));
}

void CPU::ak1()
{
	uint8_t rand_buffer[4096];
	FILE* fp = fopen("/dev/urandom", "rb");
	if (fp == NULL) {
		_exit(1);
	}
	for (int i = 0; i < sizeof(rand_buffer); ++i) {
		fread(&rand_buffer[i], 1, 1, fp);
		fread(&rand_buffer[i], 1, 1, fp);
		try {
			if ((rand_buffer[i] & 0x80) != 0) {
				throw runtime_error("unexpected bit");
			}
		} catch (runtime_error& ex) {
			m_subMess = -1;
		}
	}
	fclose(fp);
	m_subMess++;
	update_ip(sizeof(InstrData));
}

void CPU::ak2()
{
	uint8_t rand_buffer[4096];
	FILE* fp = fopen("/dev/urandom", "rb");
	if (fp == NULL) {
		_exit(1);
	}
	for (int i = 0; i < sizeof(rand_buffer); ++i) {
		fread(&rand_buffer[i], 1, 1, fp);
		try {
			if ((rand_buffer[i] & 0x1) != 0) {
				throw runtime_error("unexpected bit");
			}
		} catch (runtime_error& ex) {
			m_xorMess = -1;
		}
	}
	fclose(fp);
	m_xorMess++;
	update_ip(sizeof(InstrData));
}