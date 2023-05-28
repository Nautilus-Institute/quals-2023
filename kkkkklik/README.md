# kkkkklik

## Challenge Type

Reversing

## Difficulty level

Easy

## Description on the scoreboard

```
Find the flag.
```

## Flag

`flag{vb6_and_blowfish_fun_from_the_old_days}`

## Intended solution

- Reverse enough to realize that interesting things may happen if the picture is single-clicked for many times.
- Single-click 100 times: An input box pops up and asks for a key to encrypt a fake flag
- Single-click 133337 times: The intended password for decrypting the real flag will be drawn in the picture box, but the window is too small
- Single-click 1333337 times: The encrypted flag will be popped out. Decrypt it to get the real flag

## Acknowledgement

- Blowfish VB6 implementation: https://www.di-mgt.com.au/crypto.html#BlowfishVB
