# nlinks 

## Description on the scoreboard

```
A (binary?) ninja cut the rope of flag into many pieces.
Can you relink the rope and retrieve the flag?
```

## Flags

This challenge has two flags.
The sequence of the first N binaries is known (in their file names).
The first flag only requires the recovery of the first M bytes out of the first N binaries.
The second flag requires a full recovery of all involved bytes.

## Dependencies

```bash
$ sudo apt install build-essential \
    g++ \
    python3-pip
$ pip3 install rich networkx numba jinja2
```
