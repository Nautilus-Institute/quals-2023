#!/bin/bash

set -e
set -x

mkdir -p data

# === build_prog ===
clang --target=aarch64-pc-linux-gnu --sysroot=/sysroot -fuse-ld=lld -o /data/build_prog src/pac.c -mbranch-protection=pac-ret --static -g -DPRODUCE_CODE=1

# === run_prog ===
clang --target=aarch64v8-pc-linux-gnu --sysroot=/sysroot -o /sysroot/pac.o -c src/pac.c -mbranch-protection=pac-ret

cp /usr/bin/qemu-aarch64-static /sysroot/.

ls /sysroot
chroot /sysroot /qemu-aarch64-static /usr/bin/aarch64-linux-gnu-strip -S /pac.o --strip-unneeded

clang --target=aarch64v8-pc-linux-gnu --sysroot=/sysroot -fuse-ld=lld -o /sysroot/run_prog /sysroot/pac.o --static 

ALL_NAMES="$(chroot /sysroot /qemu-aarch64-static /usr/bin/aarch64-linux-gnu-nm /pac.o --no-demangle --defined-only | awk '{print "-N "$3}')"
ALL_NAMES="-N INPUT -N INPUT_with_val -N MEMORY_with_value -N OUTPUT -N PLACEHOLDER -N REGISTER -N _reset_circut -N add_out -N alloc_malloc_heap -N alloc_virtual_gate -N assert -N assert_m -N build_heap_backrefs -N devirtualize_gate -N g_heap -N g_num_nand_gates -N g_queue_depth -N g_start_t -N gate_heap_alloc -N gate_ring_pop -N gate_ring_push -N get_gate_val -N get_value -N get_value_bitset -N init_gate -N load_circut -N make_alu -N make_bit_andor -N make_decoder -N make_demux -N make_full_adder -N make_full_adder_bitset -N make_gate_queue -N make_gate_ring -N make_half_adder -N make_increment -N make_input_bitset -N make_memory_bitset -N make_output_bitset -N make_placeholder_bitset -N make_readonly_memory -N make_register_bank -N make_set -N make_triangle -N mux_register_bank -N mux_two -N process_output -N propigate_memory -N push_set -N push_set_bitset -N reset_circut  -N run_circut_with_info -N save_gate_heap -N seed_rand -N set_input -N set_input_bitset -N set_value -N set_value_bitset -N test_and -N test_nand -N test_or -N test_register -N test_xor"
echo $ALL_NAMES
chroot /sysroot /qemu-aarch64-static /usr/bin/aarch64-linux-gnu-strip -S /run_prog $ALL_NAMES

mv /sysroot/run_prog /data/run_prog

# === init_drm ===
clang -o /tmp/init_drm.o -c src/init_drm.c -O1
strip -S /tmp/init_drm.o
clang -o /data/init_drm /tmp/init_drm.o --static
ALL_NAMES="$(nm /tmp/init_drm.o --no-demangle --defined-only | awk '{print "-N "$3}')"
strip -S /data/init_drm $ALL_NAMES

ls /data


# === build circuits ===

make_bin() {
    touch /data/$2.bin
    chmod 666 /data/$2.bin
    /data/init_drm -l /src/$2.license /data/build_prog $1 /data/$2.bin
    chmod 644 /data/$2.bin
    cp /src/$2.license /data/.
}

make_bin triangle triangle
make_bin flag password_for_flag
#make_bin alu alu
#make_bin dmp dmp

cp /src/flag.txt /data/.

tar --numeric-owner -c -f /data/opacity_dist.tar.gz -v -z -h  dist


