#include <iostream>

#include "parser.hpp"


Parser::Parser()
    : m_vm(NULL), m_cpu(NULL), m_instr(NULL)
{

}


void Parser::parse(VM* vm, CPU* cpu, InstrData* instr)
{
    m_vm = vm;
    m_cpu = cpu;
	*instr = *((InstrData*)&m_vm->arena[m_cpu->get_ip()]);
}
