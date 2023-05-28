// Reference: x86emu/include/instruction/instruction.hpp

#ifndef _PARSER_H
#define _PARSER_H

#include "vm.hpp"
#include "cpu.hpp"
#include "instr.hpp"

class Parser {
	public:
        Parser();
		void parse(VM* vm, CPU* cpu, InstrData* instr);

        VM* m_vm;
        CPU* m_cpu;
        InstrData* m_instr;
};


#endif
