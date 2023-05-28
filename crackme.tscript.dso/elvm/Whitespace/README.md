Whitespace
==========

[![Build Status](https://travis-ci.org/koturn/Whitespace.png)](https://travis-ci.org/koturn/Whitespace)

Whitespace interpreter and C-translator.


## Usage

### Run Whitespace program

```sh
$ ./whitespace [Whitespace source file]
```

### Tanslate Whitespace to C

Specify ```-t``` flag and ```-o``` flag.

```sh
$ ./whitespace [Whitespace source file] -t -o out.c
```

If you don't specify output file with ```-o```, C source code will output
stdout.

### Options

Options                            | Function
-----------------------------------|------------------------------------
```-b```, ```--bytecode```         | Show code in hexadecimal
```-f```, ```--filter```           | Visualize whitespace source code
```-h```, ```--help```             | Show help and exit
```-m```, ```--mnemonic```         | Show byte code in mnemonic format
```-o FILE```, ```--output=FILE``` | Specify output filename
```-t```, ```--translate```        | Translate brainfuck to C source code


## Build

Use [Makefile](Makefile).

```sh
$ make
```

If you want to build with MSVC, use [msvc.mk](msvc.mk).
[msvc.mk](msvc.mk) is written for nmake.

```sh
> nmake /f msvc.mk
```


## Dependent libraries

#### MSVC only

- [getopt clone](https://github.com/koturn/getopt)


## References

- [http://compsoc.dur.ac.uk/whitespace/](http://compsoc.dur.ac.uk/whitespace/)


## LICENSE

This software is released under the MIT License, see [LICENSE](LICENSE).
