use std::{alloc::System, char, ops::Add};

use nom::{
    bits::{self, complete},
    IResult,
};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::{self, BufReader};

//define constant MEM_SIZE
const MEM_SIZE: usize = 0x1000;

use std::fs::File;
use std::io::Read;

const REG_A: u8 = 0u8;
const REG_B: u8 = 1u8;
const REG_C: u8 = 2;
const REG_D: u8 = 3;
const REG_PC: u8 = 8;
const REG_SP: u8 = 9;

enum SYSCALL_TABLE {
    EXIT = 0,
    PRINT = 1,
    PRINT_CHAR = 2,
    GET_CHAR = 3,
    OPEN_FILE = 4,
    READ_FILE = 5,
}

#[derive(Debug)]
struct cpu {
    reg: [u16; 16],
    running: bool,
    mem: [CPUInstructions; 0x1000],
    stack: [u16; 0x1000],
    files: Vec<Option<File>>,
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Register(pub u8);
#[derive(Debug, Copy, Clone, PartialEq)]
enum Operand {
    Register(Register),
    Immediate(u8),
}

impl TryFrom<u16> for SYSCALL_TABLE {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SYSCALL_TABLE::EXIT),
            1 => Ok(SYSCALL_TABLE::PRINT),
            2 => Ok(SYSCALL_TABLE::PRINT_CHAR),
            3 => Ok(SYSCALL_TABLE::GET_CHAR),
            4 => Ok(SYSCALL_TABLE::OPEN_FILE),
            5 => Ok(SYSCALL_TABLE::READ_FILE),
            _ => Err(()),
        }
    }
}

//instruction enum
#[derive(Debug, Copy, Clone, PartialEq)]
enum CPUInstructions {
    InstAdd(Register, Operand),
    InstSub(Register, Operand),
    InstLd(Register, Operand),
    InstSt(Register, Operand),
    InstSys,
    InstHlt,
    InstAnd(Register, Operand),
    InstOr(Register, Operand),
    InstXor(Register, Operand),
    InstNot(Register),
    InstShl(Register, Operand),
    InstShr(Register, Operand),
    InstJmp(Operand),
    InstCall(Operand),
    InstRet,
    InstPush(Operand),
    InstPop(Register),
    InstCmp,
    InstData(u8),
}

impl cpu {
    fn new() -> cpu {
        cpu {
            reg: [0; 16],
            running: true,
            mem: [CPUInstructions::InstHlt; 0x1000],
            stack: [0; 0x1000],
            files: Vec::new(),
        }
    }

    fn store_file(&mut self, file: File) -> u16 {
        if let Some(index) = self.files.iter().position(|f| f.is_none()) {
            self.files[index] = Some(file);
            index as u16
        } else {
            self.files.push(Some(file));
            (self.files.len() - 1) as u16
        }
    }

    fn set_register(&mut self, reg: u8, val: u16) {
        self.reg[reg as usize] = val;
    }

    fn fetch(&self) -> CPUInstructions {
        self.mem[self.reg[REG_PC as usize] as usize]
    }

    fn execute(&mut self) {
        match self.fetch() {
            CPUInstructions::InstAdd(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize].wrapping_add(self.reg[r2.0 as usize]),
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        (self.reg[r.0 as usize].wrapping_add(i as u16)).into(),
                    );
                }
            },
            CPUInstructions::InstSub(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize].wrapping_sub(self.reg[r2.0 as usize]),
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize].wrapping_sub(i as u16),
                    );
                }
            },
            CPUInstructions::InstSys => {
                let sysnum = self.reg[REG_A as usize];
                match sysnum.try_into() {
                    Ok(SYSCALL_TABLE::EXIT) => {
                        self.running = false;
                    }
                    Ok(SYSCALL_TABLE::PRINT) => {
                        print!("{}", self.reg[REG_B as usize]);
                    }
                    Ok(SYSCALL_TABLE::PRINT_CHAR) => {
                        let output = self.reg[REG_B as usize].to_be_bytes()[1];
                        print!("{}", output as char);
                    }
                    Ok(SYSCALL_TABLE::GET_CHAR) => {
                        let mut input = String::new();
                        std::io::stdin()
                            .read_line(&mut input)
                            .expect("Failed to read line");
                        self.set_register(REG_B, input.chars().next().unwrap() as u16);
                    }
                    Ok(SYSCALL_TABLE::OPEN_FILE) => {
                        let filename_addr = self.reg[REG_B as usize];
                        let filename = read_null_terminated_string(self, filename_addr);

                        if filename == "flag" {
                            let file = std::fs::File::open(&filename).expect("Unable to open file");
                            let file_descriptor = self.store_file(file); // Implement a function to store the file and return a file descriptor.
                            self.set_register(REG_C, file_descriptor);
                        } else {
                            println!("Error: Unable to open file '{}'", filename);
                            self.set_register(REG_C, u16::MAX); // Set an error code (e.g., u16::MAX) in REG_C to indicate failure.
                        }
                    }
                    Err(_) => {
                        println!("Invalid syscall number {}", sysnum);
                    }
                    Ok(SYSCALL_TABLE::READ_FILE) => {
                        let fd = self.reg[REG_B as usize] as usize;
                        let buf_addr = self.reg[REG_C as usize];
                        let size = self.reg[REG_D as usize] as usize;

                        if let Some(file) = self.files.get_mut(fd).and_then(|f| f.as_mut()) {
                            let mut buffer = vec![0; size];
                            let read_size = file.read(&mut buffer).unwrap_or(0);

                            for (i, byte) in buffer.into_iter().enumerate() {
                                if i < read_size {
                                    self.stack[(buf_addr as usize + i) % MEM_SIZE] = byte as u16;
                                } else {
                                    break;
                                }
                            }

                            self.set_register(REG_B, read_size as u16);
                        } else {
                            println!("Invalid file descriptor {}", fd);
                        }
                    }
                }
            }
            CPUInstructions::InstAnd(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize] & self.reg[r2.0 as usize],
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(r.0.try_into().unwrap(), self.reg[r.0 as usize] & (i as u16));
                }
            },
            CPUInstructions::InstOr(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize] | self.reg[r2.0 as usize],
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(r.0.try_into().unwrap(), self.reg[r.0 as usize] | (i as u16));
                }
            },
            CPUInstructions::InstXor(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize] ^ self.reg[r2.0 as usize],
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(r.0.try_into().unwrap(), self.reg[r.0 as usize] ^ (i as u16));
                }
            },
            CPUInstructions::InstNot(r) => {
                self.set_register(r.0, !self.reg[r.0 as usize]);
            }
            CPUInstructions::InstShl(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize] << self.reg[r2.0 as usize],
                    );
                }
                Operand::Immediate(i) => {
                    self.set_register(
                        r.0.try_into().unwrap(),
                        self.reg[r.0 as usize] << (i as u16),
                    );
                }
            },
            CPUInstructions::InstShr(r, o) => {
                let shift_amount = match o {
                    Operand::Register(r2) => self.reg[r2.0 as usize] & 0xF,
                    Operand::Immediate(i) => (i & 0xF) as u16,
                };
                self.set_register(r.0, self.reg[r.0 as usize] >> shift_amount);
            }
            CPUInstructions::InstJmp(o) => {
                self.reg[REG_PC as usize] += 1;
                match o {
                    Operand::Register(r) => {
                        self.set_register(REG_PC, self.reg[r.0 as usize]);
                    }
                    Operand::Immediate(i) => {
                        self.set_register(REG_PC, i as u16);
                    }
                }
                return;
            }
            CPUInstructions::InstCall(o) => {
                self.reg[REG_PC as usize] += 1;
                match o {
                    Operand::Register(r) => {
                        self.stack[self.reg[REG_SP as usize] as usize] =
                            self.reg[REG_PC as usize] + 1;
                        self.reg[REG_SP as usize] += 1;
                        self.reg[REG_PC as usize] = self.reg[r.0 as usize];
                    }
                    Operand::Immediate(i) => {
                        self.stack[self.reg[REG_SP as usize] as usize] =
                            self.reg[REG_PC as usize] + 1;
                        self.reg[REG_SP as usize] += 1;
                        self.reg[REG_PC as usize] = self.reg[REG_PC as usize] + i as u16;
                    }
                }
                self.reg[REG_PC as usize] += 1;
                return;
            }
            CPUInstructions::InstRet => {
                self.set_register(REG_PC, self.stack[self.reg[REG_SP as usize] as usize - 1]);
                self.set_register(REG_SP, self.reg[REG_SP as usize] - 1);
                return;
            }
            CPUInstructions::InstPush(o) => match o {
                Operand::Register(r) => {
                    self.stack[self.reg[REG_SP as usize] as usize] = self.reg[r.0 as usize];
                    self.set_register(REG_SP, self.reg[REG_SP as usize] + 1);
                }
                Operand::Immediate(i) => {
                    self.stack[self.reg[REG_SP as usize] as usize] = i as u16;
                    self.set_register(REG_SP, self.reg[REG_SP as usize] + 1);
                }
            },
            CPUInstructions::InstPop(r) => {
                self.set_register(r.0, self.stack[self.reg[REG_SP as usize - 1] as usize]);
                self.set_register(REG_SP, self.reg[REG_SP as usize] - 1);
            }
            CPUInstructions::InstSt(r, o) => match o {
                Operand::Register(r2) => {
                    self.stack[self.reg[r2.0 as usize] as usize] = self.reg[r.0 as usize];
                }
                Operand::Immediate(i) => {
                    self.stack[self.reg[r.0 as usize] as usize] = i as u16;
                }
            },
            CPUInstructions::InstLd(r, o) => match o {
                Operand::Register(r2) => {
                    self.set_register(r.0, self.stack[self.reg[r2.0 as usize] as usize]);
                }
                //todo: bug
                Operand::Immediate(i) => {
                    self.set_register(r.0, self.stack[i as usize]);
                }
            },
            /*CPUInstructions::InstCmp => {
                println!("cmp");
            }*/
            CPUInstructions::InstHlt => {
                self.running = false;
                return;
            }
            _ => {}
        }
        self.reg[REG_PC as usize] += 1;
    }
}

fn main() {
    let mut instructionsRetired = 0;
    loop {
        let mut cpu = cpu::new();
        let mut stdin = io::stdin();

        let mut program: Vec<u16> = Vec::new();

        let mut numInsts = 0_u16;

        let mut tmpBuf = [0u8; 2];

        stdin.read_exact(&mut tmpBuf).unwrap();
        numInsts = u16::from_le_bytes(tmpBuf);

        if numInsts > 1000 {
            println!("Program too large!");
            return;
        }

        for i in 0..numInsts {
            let mut bytes = [0u8; 2];
            stdin.read_exact(&mut bytes).unwrap();
            program.push(u16::from_le_bytes(bytes));
        }

        for (index, opcode) in program.iter().enumerate() {
            cpu.mem[index] = parse_opcode(*opcode);
        }
        while cpu.running == true {
            cpu.execute();
            instructionsRetired += 1;
            if instructionsRetired > 10000 {
                println!("Executed too many instructions")
                return;
            }
        }
        println!("\nExecution halted!");
        println!(
            "A: {:?} B: {:?} C: {:?} D: {:?}: PC: {:?} SP: {:?}",
            cpu.reg[REG_A as usize],
            cpu.reg[REG_B as usize],
            cpu.reg[REG_C as usize],
            cpu.reg[REG_D as usize],
            cpu.reg[REG_PC as usize],
            cpu.reg[REG_SP as usize]
        );
        //ask the user if they'd like to start over.
        println!("Would you like to start over? (y/n)");
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        if input.trim() != "y" {
            return;
        }
    }
}

fn parse_opcode(opcode: u16) -> CPUInstructions {
    let operation = (opcode >> 12) & 0xF;
    let destination = ((opcode >> 8) & 0xF) as u8;
    let source = (opcode & 0xFF) as u8;

    let dest_reg = Register(destination);
    let src_operand = if source & 0x80 == 0 {
        Operand::Register(Register(source & 0xF))
    } else {
        Operand::Immediate(source & 0x7F)
    };
    match operation {
        0 => CPUInstructions::InstAdd(dest_reg, src_operand),
        1 => CPUInstructions::InstSub(dest_reg, src_operand),
        2 => CPUInstructions::InstLd(dest_reg, src_operand),
        3 => CPUInstructions::InstSt(dest_reg, src_operand),
        4 => CPUInstructions::InstAnd(dest_reg, src_operand),
        5 => CPUInstructions::InstOr(dest_reg, src_operand),
        6 => CPUInstructions::InstXor(dest_reg, src_operand),
        7 => CPUInstructions::InstNot(dest_reg),
        8 => CPUInstructions::InstShl(dest_reg, src_operand),
        9 => CPUInstructions::InstShr(dest_reg, src_operand),
        10 => CPUInstructions::InstJmp(src_operand),
        11 => CPUInstructions::InstCall(src_operand),
        12 => CPUInstructions::InstCmp,
        13 => CPUInstructions::InstPush(src_operand),
        14 => CPUInstructions::InstPop(dest_reg),
        15 => match destination {
            0 => CPUInstructions::InstSys,
            1 => CPUInstructions::InstHlt,
            2 => CPUInstructions::InstRet,
            _ => CPUInstructions::InstHlt,
        },
        _ => CPUInstructions::InstHlt,
    }
}

fn read_null_terminated_string(cpu: &cpu, addr: u16) -> String {
    let mut string = String::new();
    let mut current_addr = addr;
    let mut data: char;

    while let data = cpu.stack[current_addr as usize] {
        if data == 0 {
            break;
        } else {
            string.push(char::from_u32(data as u32).unwrap());
        }
        current_addr += 1;
    }

    string
}
