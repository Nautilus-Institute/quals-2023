// Reference: x86emu/include/instruction/instruction.hpp

#ifndef _INSTR_H
#define _INSTR_H

#include <map>

#define EMU				get_emu()
#define GET_IP()			EMU->get_ip()
#define SET_IP(v)			EMU->set_ip(v)
#define UPDATE_EIP(v)			m_cpu->update_eip(v)
#define GET_GPREG(reg)			EMU->get_gpreg(reg)
#define SET_GPREG(reg, v)		EMU->set_gpreg(reg, v)
#define UPDATE_GPREG(reg, v)		EMU->update_gpreg(reg, v)

#define READ_MEM32(addr)		EMU->get_data32(addr)
#define READ_MEM16(addr)		EMU->get_data16(addr)
#define READ_MEM8(addr)			EMU->get_data8(addr)
#define WRITE_MEM32(addr, v)		EMU->put_data32(addr, v)
#define WRITE_MEM16(addr, v)		EMU->put_data16(addr, v)
#define WRITE_MEM8(addr, v)		EMU->put_data8(addr, v)
#define PUSH64(v)			EMU->push64(v)
#define PUSH32(v)			EMU->push32(v)
#define PUSH16(v)			EMU->push16(v)
#define POP64()				EMU->pop64()
#define POP32()				EMU->pop32()
#define POP16()				EMU->pop16()

#define MAX_OPCODE	0x200

#define OPT_REG 1
#define OPT_IMM 2
#define OPT_MEM 3
#define OPT_MEMREG 4

/* BEGIN */
#define OP_ADD 13
#define OP_SUB 14
#define OP_XOR 15
#define OP_SAL 16
#define OP_AND 17
#define OP_OR  18
#define OP_JMP 20
#define OP_JE  21
#define OP_JNE 22
#define OP_JA  23
#define OP_JAE 24
#define OP_JB  25
#define OP_JBE 26
#define OP_JG  27
#define OP_JGE 28
#define OP_JL  29
#define OP_JLE 30
#define OP_CALL 31
#define OP_RET 32
#define OP_LEA 33
#define OP_MOV 34
#define OP_AK0 40
#define OP_AK1 41
#define OP_AK2 42
/* END */

#define FUNC_READ 0
#define FUNC_PRINTF 1


#pragma pack(1)
struct InstrData {
	uint16_t opcode;
	uint8_t op0_type;
	uint64_t op0;
	uint8_t op1_type;
	uint64_t op1;
	uint8_t op2_type;
	uint64_t op2;
};
#pragma pack()

#endif