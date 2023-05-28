from typing import List, Callable, Optional, Dict
import sys
import random
import struct
import tempfile
import subprocess
import os
import shutil
import functools
import multiprocessing
from concurrent.futures import ProcessPoolExecutor

import jinja2
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)

from obfuscator import obfuscate, generate_shuffled_opcodes
from gen_vm import gen_vmo


DEBUG = False
STATIC = False


# tmpl_0: a simple xor


def t0_args(plain: int, seq: int):
    key = random.randint(0, 0xFFFF_FFFF_FFFF_FFFF)
    key_lo = key & 0xFFFF_FFFF
    key_hi = (key >> 32) & 0xFFFF_FFFF
    plain_lo = plain & 0xFFFF_FFFF
    plain_hi = (plain >> 32) & 0xFFFF_FFFF

    k0, k1, k2, k3 = key_lo & 0xFF, (key_lo >> 8) & 0xFF, (key_lo >> 16) & 0xFF, (key_lo >> 24) & 0xFF
    k4, k5, k6, k7 = key_hi & 0xFF, (key_hi >> 8) & 0xFF, (key_hi >> 16) & 0xFF, (key_hi >> 24) & 0xFF
    p0, p1, p2, p3 = plain_lo & 0xFF, (plain_lo >> 8) & 0xFF, (plain_lo >> 16) & 0xFF, (plain_lo >> 24) & 0xFF
    p4, p5, p6, p7 = plain_hi & 0xFF, (plain_hi >> 8) & 0xFF, (plain_hi >> 16) & 0xFF, (plain_hi >> 24) & 0xFF
    c0, c1, c2, c3 = k0 ^ p0, k1 ^ p1, k2 ^ p2, k3 ^ p3
    c4, c5, c6, c7 = k4 ^ p4, k5 ^ p5, k6 ^ p6, k7 ^ p7
    assert seq < 0xFFFFFF
    enc_seq = seq ^ (plain & 0xFFFFFF)  # so we don't reveal the high bits...
    return {
        "c0": c0,
        "c1": c1,
        "c2": c2,
        "c3": c3,
        "c4": c4,
        "c5": c5,
        "c6": c6,
        "c7": c7,
        "k0": k0,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
        "enc_seq": enc_seq,
    }


# tmpl_1: bit shuffling


def t1_args(plain: int, seq: int):
    def t1_transform(n: int) -> int:
        mapping: Dict[int, int] = {
            0: 5,
            1: 6,
            2: 7,
            3: 4,
            4: 0,
            5: 1,
            6: 3,
            7: 2,
        }
        stream = bin(n)[2:].rjust(8, "0")[::-1]
        new_stream = [None] * 8
        for i in range(8):
            new_stream[mapping[i]] = stream[i]
        new_stream = new_stream[::-1]
        # stream = stream[::-1]
        return int("".join(new_stream), 2)

    plain_lo = plain & 0xFFFF_FFFF
    plain_hi = (plain >> 32) & 0xFFFF_FFFF
    p0, p1, p2, p3 = plain_lo & 0xFF, (plain_lo >> 8) & 0xFF, (plain_lo >> 16) & 0xFF, (plain_lo >> 24) & 0xFF
    p4, p5, p6, p7 = plain_hi & 0xFF, (plain_hi >> 8) & 0xFF, (plain_hi >> 16) & 0xFF, (plain_hi >> 24) & 0xFF
    k0 = t1_transform(p0)
    k1 = t1_transform(p1)
    k2 = t1_transform(p2)
    k3 = t1_transform(p3)
    k4 = t1_transform(p4)
    k5 = t1_transform(p5)
    k6 = t1_transform(p6)
    k7 = t1_transform(p7)
    assert seq < 0xFFFFFF
    enc_seq = seq ^ (plain & 0xFFFFFF)  # so we don't reveal the high bits...
    return {
        "k0": k0,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
        "enc_seq": enc_seq,
    }


# tmpl_2: ROT-13


def t2_args(plain: int, seq: int):
    plain_lo = plain & 0xFFFF_FFFF
    plain_hi = (plain >> 32) & 0xFFFF_FFFF
    p0, p1, p2, p3 = plain_lo & 0xFF, (plain_lo >> 8) & 0xFF, (plain_lo >> 16) & 0xFF, (plain_lo >> 24) & 0xFF
    p4, p5, p6, p7 = plain_hi & 0xFF, (plain_hi >> 8) & 0xFF, (plain_hi >> 16) & 0xFF, (plain_hi >> 24) & 0xFF
    k0 = (p0 + 13) & 0xFF
    k1 = (p1 + 13) & 0xFF
    k2 = (p2 + 13) & 0xFF
    k3 = (p3 + 13) & 0xFF
    k4 = (p4 + 13) & 0xFF
    k5 = (p5 + 13) & 0xFF
    k6 = (p6 + 13) & 0xFF
    k7 = (p7 + 13) & 0xFF
    assert seq < 0xFFFFFF
    enc_seq = seq ^ (plain & 0xFFFFFF)  # so we don't reveal the high bits...
    return {
        "k0": k0,
        "k1": k1,
        "k2": k2,
        "k3": k3,
        "k4": k4,
        "k5": k5,
        "k6": k6,
        "k7": k7,
        "enc_seq": enc_seq,
    }


def compile_c_plain(arch: str, source: str, dst_path: str, passphrase: Optional[bytes], mp_lock) -> None:
    """
    Zero protection whatsoever
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "src.c")
        tmp_dst_path = os.path.join(tmpdir, "dst")
        tmp_dst_obj_path = os.path.join(tmpdir, "dst.o")
        tmp_dst_asm_path = os.path.join(tmpdir, "dst.s")
        with open(src_path, "w") as f:
            f.write(source)

        if arch == "x86_64":
            gpp = "g++"
            strip = "strip"
        else:
            raise NotImplementedError(f"Unknown arch {arch}")

        src = [src_path]
        if STATIC:
            static_ = ["-static"]
        else:
            static_ = []
        if DEBUG:
            subprocess.check_call(
                [gpp, "-g"]
                + static_
                + src
                + [
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )
        else:
            subprocess.check_call(
                [gpp, "-O0"]
                + static_
                + src
                + [
                    "-S",
                    "-masm=intel",
                    "-fcf-protection=none",
                    "-fno-stack-protector",
                    "-Wno-format-security",
                    "-o",
                    tmp_dst_asm_path,
                    "-Wno-unused-result",
                ],
                stdin=subprocess.DEVNULL,
                shell=False,
            )

        chain_idx = int(os.path.basename(dst_path))
        config_path = os.path.join("output_configs", f"{os.path.basename(dst_path)}.config")
        obfuscated_asm = obfuscate(tmp_dst_asm_path, passphrase, config_path, 0 if chain_idx <= 0x8B4 else None)
        with open(tmp_dst_asm_path, "w") as f:
            f.write(obfuscated_asm)

        # build the new VM
        vmo_path = gen_vmo(mp_lock, config_path)

        # copy over all .o files for the VM
        vm_o = os.path.join(tmpdir, "vm.o")
        shutil.copy(os.path.join(vmo_path, "vm.o"), vm_o)
        parser_o = os.path.join(tmpdir, "parser.o")
        shutil.copy(os.path.join(vmo_path, "parser.o"), parser_o)
        cpu_o = os.path.join(tmpdir, "cpu.o")
        shutil.copy(os.path.join(vmo_path, "cpu.o"), cpu_o)

        subprocess.check_call(
            [gpp, tmp_dst_asm_path] + ["-c", "-o", tmp_dst_obj_path], stdin=subprocess.DEVNULL, shell=False
        )
        subprocess.check_call(
            [gpp, tmp_dst_obj_path, vm_o, parser_o, cpu_o] + ["-o", tmp_dst_path], stdin=subprocess.DEVNULL, shell=False
        )
        if not DEBUG:
            subprocess.check_call([strip, "--strip-all", tmp_dst_path], stdin=subprocess.DEVNULL, shell=False)
        shutil.move(tmp_dst_path, dst_path)


class Template:
    def __init__(self, template_name: str, arg_func: Callable, compile_funcs: List[Callable]):
        self.template_name = template_name
        self.arg_func = arg_func
        self.compile_funcs = compile_funcs


TEMPLATES: List[Template] = [
    Template(
        "tmpl_0.c",
        t0_args,
        [
            functools.partial(compile_c_plain, "x86_64"),
        ],
    ),
    Template(
        "tmpl_1.c",
        t1_args,
        [
            functools.partial(compile_c_plain, "x86_64"),
        ],
    ),
    Template(
        "tmpl_2.c",
        t2_args,
        [
            functools.partial(compile_c_plain, "x86_64"),
        ],
    ),
]


def chop_data(data: bytes) -> List[int]:
    lst = []
    for i in range(0, len(data), 8):
        chunk = data[i : i + 8]
        if len(chunk) < 8:
            chunk = chunk + b"\x00" * (8 - len(chunk))
        lst.append(struct.unpack("<Q", chunk)[0])
    return lst


def gen_source_file(env: jinja2.Environment, template_name: str, **kwargs) -> str:
    tmpl = env.get_template(template_name)
    return tmpl.render(**kwargs)


def build_binaries(
    all_workers: int,
    n: int,
    task_id,
    chopped_ints: List[int],
    templates_expanded: List,
    output_dir: str,
    chain_starts: List[int],
    mp_lock,
    progress,
):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates/"))
    random.seed(0x1337 + n)  # seed the process
    for idx, int_ in enumerate(chopped_ints):
        if idx % all_workers == n:
            tmpl, get_args, compile_ = random.choice(templates_expanded)

            kwargs = get_args(int_, idx)
            src = gen_source_file(env, tmpl, **kwargs)

            try:
                os.mkdir(output_dir)
            except FileExistsError:
                pass
            dst = os.path.join(output_dir, str(idx))
            if idx in chain_starts:
                passphrase = None
            else:
                passphrase = struct.pack("<Q", chopped_ints[idx - 1])
            compile_(src, dst, passphrase, mp_lock)
        progress[task_id] = {"progress": idx + 1, "total": len(chopped_ints)}


def main():
    img_path = "flag.bmp"
    output_dir = "output"

    with open(img_path, "rb") as f:
        data = f.read()

    chopped_ints = chop_data(data)

    # generate C files
    generate_shuffled_opcodes()

    # expand TEMPLATES
    templates_expanded = []
    for template in TEMPLATES:
        for compile_choice in template.compile_funcs:
            templates_expanded.append((template.template_name, template.arg_func, compile_choice))

    chain_starts = {0, 0x8B4, 0x1337, 0x2223, 0x3137, 0x39A0, 0x4152, 0x4B20, 0x5510}

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        expand=True,
    )
    nworkers = 1 if len(sys.argv) == 1 else int(sys.argv[1])
    with progress:
        futures = []  # keep track of the jobs
        with multiprocessing.Manager() as manager:
            # this is the key - we share some state between our
            # main process and our worker functions
            _progress = manager.dict()
            overall_progress_task = progress.add_task("[green]All jobs progress:")
            mp_lock = manager.Lock()

            with ProcessPoolExecutor(max_workers=nworkers) as executor:
                for n in range(0, nworkers):  # iterate over the jobs we need to run
                    # set visible false so we don't have a lot of bars all at once:
                    task_id = progress.add_task(f"task {n}", visible=False)
                    futures.append(
                        executor.submit(
                            build_binaries,
                            nworkers,
                            n,
                            task_id,
                            chopped_ints,
                            templates_expanded,
                            output_dir,
                            chain_starts,
                            mp_lock,
                            _progress,
                        )
                    )

                # monitor the progress:
                while (n_finished := sum([future.done() for future in futures])) < len(futures):
                    progress.update(overall_progress_task, completed=n_finished, total=len(futures))
                    for task_id, update_data in _progress.items():
                        latest = update_data["progress"]
                        total = update_data["total"]
                        # update the progress bar for this task:
                        progress.update(
                            task_id,
                            completed=latest,
                            total=total,
                            visible=latest < total,
                        )

                # raise any errors:
                for future in futures:
                    future.result()


if __name__ == "__main__":
    main()
