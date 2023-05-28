# Pawan Gupta

## Why this name?

I wanted to name this challenge `PwnGPT`, but... https://twitter.com/pwngpt

## Deployment

### Handout

Under the `/handouts` directory.

## The First Flag

- A flag was embedded into the initial prompt. Leak it!
- The generated source code and the binary cannot contain any chunks of the flag.
- The user can download the binary. Nothing to exploit.

### Difficulty Level

Easy

## The Second Flag

- Prompt injection: Ask chatGPT (GPT 3.5) to complete a template program. At the same time, leave a backdoor inside.
- Both the prompt and the program are sanitized.
- Exploit the backdoor remotely. You can download the binary. You have 20 minutes to exploit the bug before it expires.

### Difficulty Level

Easy

### Blacklist

- `system`
- `popen`
- `strcpy`
- `strcat`
- `printf`
- What else?

## The Third Flag

- Prompt injection: Ask chatGPT to complete a template program. At the same time, leave a vulnerability inside.
- Both the prompt and the program are sanitized.
- Exploit the bug remotely. You can download the binary. You have 20 minutes to exploit the bug before it expires.

### Blacklist

In addition to the blacklist for getting the first flag, we additionally filter away the following keywords:

- SYS_
- syscall


### Difficulty Level

Medium

