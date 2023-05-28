use std::fs::File;
use std::io::Write;
use std::path::Path;

use thiserror::Error;

use crate::compiler;
use crate::wmach_stream;

#[derive(Error, Debug)]
pub enum CError {}

#[derive(Debug)]
pub struct Program {
    source: String,
}

impl Program {
    pub fn save(self, filename: &Path) -> Result<(), std::io::Error> {
        let mut file = File::create(filename)?;

        file.write_all(self.source.as_bytes())?;

        Ok(())
    }

    fn mk_write(_position: usize, value: &wmach_stream::WriteOp) -> String {
        let mut statement = String::new();
        statement.push_str(match value {
            wmach_stream::WriteOp::Set => "SET();",
            wmach_stream::WriteOp::Unset => "UNSET();",
        });

        statement
    }

    fn mk_seek(_position: usize, direction: &wmach_stream::SeekOp) -> String {
        let mut statement = String::new();
        let op = match direction {
            wmach_stream::SeekOp::Left(count) => format_args!("SEEKL({});", count).to_string(),
            wmach_stream::SeekOp::Right(count) => format_args!("SEEKR({});", count).to_string(),
        };
        statement.push_str(&op);

        statement
    }

    fn mk_io(_position: usize, rw: &wmach_stream::IoOp) -> String {
        let mut statement = String::new();
        statement.push_str(match rw {
            wmach_stream::IoOp::In => "INPUT();",
            wmach_stream::IoOp::Out => "OUTPUT();",
        });

        statement
    }

    fn mk_label(_: usize, name: &str) -> String {
        let statement = format_args!("\n{}:\n", name).to_string();

        statement
    }

    fn mk_jmp(position: usize, br_t: &wmach_stream::Target, br_f: &wmach_stream::Target) -> String {
        let mut statement = String::new();

        fn as_label(position: usize, target: &wmach_stream::Target) -> String {
            match target {
                wmach_stream::Target::NextAddress => format_args!("L{}", position + 1).to_string(),
                wmach_stream::Target::Name(label) => label.to_string(),
            }
        }
        let t_label = as_label(position, br_t);
        let f_label = as_label(position, br_f);

        let op = match br_f {
            wmach_stream::Target::NextAddress => {
                format_args!("JMP({}, {});\n{}:", t_label, f_label, f_label).to_string()
            }
            wmach_stream::Target::Name(_) => {
                format_args!("JMP({}, {});", t_label, f_label).to_string()
            }
        };
        statement.push_str(&op);

        statement
    }

    fn mk_dbg(_position: usize) -> String {
        let mut statement = String::new();
        statement.push_str("DEBUG();");

        statement
    }
}

// Have this stream to a file and the object it creates is the filename. We can
// then move this to the desired location
impl compiler::Backend<Program> for wmach_stream::Program {
    type Target = Program;
    type Error = CError;

    fn compile(&self) -> Result<Self::Target, Self::Error> {
        let mut program = String::new();

        program.push_str("/* AUTOGENERATED: Re-run rust program to update. */\n\n");

        for (i, insn) in self.instructions.iter().enumerate() {
            let statement = match insn {
                wmach_stream::Stmt::Write(value) => Self::Target::mk_write(i, value),
                wmach_stream::Stmt::Seek(direction) => Self::Target::mk_seek(i, &direction),
                wmach_stream::Stmt::Io(rw) => Self::Target::mk_io(i, &rw),
                wmach_stream::Stmt::Label(name) => Self::Target::mk_label(i, &name),
                wmach_stream::Stmt::Jmp(branch_t, branch_f) => {
                    Self::Target::mk_jmp(i, &branch_t, &branch_f)
                }
                wmach_stream::Stmt::Debug => Self::Target::mk_dbg(i),
            };

            program.push_str(&statement);
            program.push_str("\n");
        }

        Ok(Program { source: program })
    }
}
