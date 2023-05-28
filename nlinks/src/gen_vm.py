# Generate a VM with varied operands
from typing import List, Tuple
import sys
import json
import hashlib
import os.path
import shutil
import subprocess

BASEDIR = os.path.realpath(os.path.dirname(__file__))


def gen_vmo(lock, config_file: str):
    with open(config_file, "r") as f:
        data = f.read()
        config: List[Tuple[str, str]] = json.loads(data)

    hash = hashlib.md5(data.encode("utf-8")).hexdigest()

    vmo_dst = os.path.join(BASEDIR, "..", f"vmos/{hash}")
    if (
        os.path.isfile(os.path.join(vmo_dst, "cpu.o"))
        and os.path.isfile(os.path.join(vmo_dst, "vm.o"))
        and os.path.isfile(os.path.join(vmo_dst, "parser.o"))
    ):
        # fast path
        return vmo_dst
    with lock:
        if not os.path.isdir(vmo_dst) or not os.path.isfile(os.path.join(vmo_dst, "cpu.o")):
            shutil.rmtree(vmo_dst, ignore_errors=True)
            # copy the entire vmo directory
            shutil.copytree(os.path.join(BASEDIR, "..", "vmo"), vmo_dst)

            # replace the opcode definition
            with open(os.path.join(vmo_dst, "instr.hpp"), "r") as f:
                lines = f.read().split("\n")
            begin = lines.index("/* BEGIN */")
            end = lines.index("/* END */")
            assert begin != -1
            assert end != -1
            lines = lines[: begin + 1] + [f"#define OP_{k.upper()} {v}" for k, v in config] + lines[end:]
            with open(os.path.join(vmo_dst, "instr.hpp"), "w") as f:
                f.write("\n".join(lines))

            # run make
            subprocess.check_call(
                ["make", "clean"],
                cwd=vmo_dst,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.check_call(
                ["make", "objs"],
                cwd=vmo_dst,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    return vmo_dst


if __name__ == "__main__":
    config_file = sys.argv[1]
    gen_vmo(None, config_file)
