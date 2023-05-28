#!/usr/bin/env python
import sys
import time
import socket
import select

ADDR = "localhost"

class Guard:
    def __init__(self, name: str, port: int):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ADDR, port))

    def talk(self):
        data = self.sock.recv(1024)
        if len(data) == 0:
            talkers.remove(self)
            socket.close(self.fileno())
            return
        print(f"{self.name}: {data.decode('utf-8').strip()}")

    def fileno(self):
        return self.sock.fileno()

    def recv(self, num):
        return self.sock.recv(num)

    def speakTo(self, words):
        self.sock.send(words)

    def name(self):
        return self.name

class Speaker:
    def fileno(self):
        return sys.stdin.fileno()

    def talk(self):
        foo = sys.stdin.readline()
        (requestedName,_,what) = foo.partition(":")
        try:
            who = [guard for guard in talkers if guard.name == requestedName]
            who[0].speakTo(bytes(what, 'utf-8'))
        except IndexError:
            print("Nobody here by that name...")

    def name(self):
        return "Yourself"

talkers = []

def main():
    
    speaker = Speaker()
    talkers.append(Guard("Bob", 6900))
    talkers.append(Guard("Charles", 6901))
    talkers.append(Guard("Sam", 6902))
    talkers.append(speaker)
    while(True):
        (got, want, _) = select.select( talkers, [], [])
        for guard in got:
            guard.talk()

if __name__ == "__main__":
    main()
