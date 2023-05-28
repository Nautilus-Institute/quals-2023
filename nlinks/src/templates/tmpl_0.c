// the simplest encryption: xor

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

int main()
{
    // cipher text
    uint8_t c0 = {{c0}}, c1 = {{c1}}, c2 = {{c2}}, c3 = {{c3}},
            c4 = {{c4}}, c5 = {{c5}}, c6 = {{c6}}, c7 = {{c7}};
    // key
    uint8_t k0 = {{k0}}, k1 = {{k1}}, k2 = {{k2}}, k3 = {{k3}},
            k4 = {{k4}}, k5 = {{k5}}, k6 = {{k6}}, k7 = {{k7}};
    // plain text (user input)
    uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;

    // Read input
    read(0, &p0, 1);
    read(0, &p1, 1);
    read(0, &p2, 1);
    read(0, &p3, 1);
    read(0, &p4, 1);
    read(0, &p5, 1);
    read(0, &p6, 1);
    read(0, &p7, 1);

    c0 ^= p0;
    c1 ^= p1;
    c2 ^= p2;
    c3 ^= p3;
    c4 ^= p4;
    c5 ^= p5;
    c6 ^= p6;
    c7 ^= p7;

    if (c0 == k0 && c1 == k1 && c2 == k2 && c3 == k3
            && c4 == k4 && c5 == k5 && c6 == k6 && c7 == k7) {
        // sequence
        uint64_t p = p0 | (p1 << 8) | (p2 << 16) | (p3 << 24) | (p4 << 32) | (p5 << 40) | (p6 << 48) | (p7 << 56);
        char fmt[] = "ID: %llu\n";
        printf(fmt, {{enc_seq}}ULL ^ (p & 0xffffff));
        return 0;
    }
    char str[] = ":(\n";
    printf(str);
    return -1;
}
