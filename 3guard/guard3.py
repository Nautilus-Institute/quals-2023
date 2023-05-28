#!/usr/bin/env python

import random
import socketserver
import pyseccomp as seccomp

# Command handlers
def handle_deal(arg):
    return 'I am annoyed by people who try to do clever things with files'

def handle_exec(arg, loc={}):
    exec(arg, {}, loc)
    return "Sure thing, boss"

COMMANDS = {
    'What is your deal?': handle_deal,
    'exec' : handle_exec,
}

def banter():
    return random.choice([
        "I don't know, I wasn't really paying attention.",
        "I was just taking a quick nap, no big deal.",
        "Sorry, I was on my phone and didn't see anything.",
        "Well, it wasn't my break time yet, so I didn't bother.",
        "Who cares if I let them in? They looked fine to me.",
        "Honestly, I don't remember if I locked the gate or not.",
        "I forgot to check their ID, but they seemed trustworthy.",
        "I didn't report it because it seemed like too much paperwork.",
        "Why bother with the security cameras? They never show anything interesting.",
        "I can't be expected to keep an eye on everything all the time.",
        "I don't get paid enough to deal with this.",
        "Yeah, I saw them, but it wasn't my problem.",
        "I gave my buddy the security code, he just wanted to see the place.",
        "I don't see the point of these constant patrols.",
        "I just let anyone in who says they work here.",
        "Sure, I leave the keys lying around, but who would steal them?",
        "Checking bags is a waste of time, nobody ever has anything.",
        "I don't see why I need to be sober to do this job.",
        "They didn't look suspicious to me, so I let them go.",
        "I haven't really read the security protocols, they're boring."
    ])

class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # Receive the data
        while True:
            data = self.request.recv(1024)
            if not data:
                break
            command = data.decode().strip()
            (command,_, arg) = command.partition(":")
            if command in COMMANDS:
                response = COMMANDS[command](arg)
                self.request.sendall(response.encode())
            else:
                msg = banter()
                self.request.sendall(msg.encode())

def drop_perms():
    # create a new seccomp filter
    filter = seccomp.SyscallFilter(seccomp.KILL)
    #skip these, even if they're in the top 75
    avoid = [0, 2, 17, 19, 40, 56, 59]
    # allow only the first 50 syscalls
    for i in range(0, 70):
        if i in avoid:
            continue
        filter.add_rule(seccomp.ALLOW, i)
    filter.add_rule(seccomp.ALLOW, 285)
    filter.add_rule(seccomp.ALLOW, 286)
    filter.add_rule(seccomp.ALLOW, 287)
    filter.add_rule(seccomp.ALLOW, 288)
    filter.add_rule(seccomp.ALLOW, 289)
    filter.add_rule(seccomp.ALLOW, 290)


    # load the filter into the current process
    filter.load()

def start_server(host = 'localhost', port = 6902):
    server_address = (host, port)
    server = socketserver.TCPServer(server_address, TCPHandler)

    drop_perms()
    
    # Start the server
    server.serve_forever()


if __name__ == "__main__":
    start_server()

