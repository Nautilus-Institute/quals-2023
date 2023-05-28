# Open House #

This is a re-write of "tomato" from the DEF CON 19 finals, with a bit of a twist.

The original was an x86 FreeBSD binary with executable stack, no ASLR, and no other protections. This one has been modernized a bit, but should still be pretty easy. The solution doesn't require having libc on-hand, so we only distribute the binary itself.

