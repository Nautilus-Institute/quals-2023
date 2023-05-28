// also very simple: bit-shifting

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// 0 -> 5
// 1 -> 6
// 2 -> 7
// 3 -> 4
// 4 -> 0
// 5 -> 1
// 6 -> 3
// 7 -> 2
#define TRANSFORM(x) { \
        if ((x & 1) != 0) { \
            t |= 0x20; \
        } else { \
            t &= ~0x20; \
        } \
        if ((x & 2) != 0) { \
            t |= 0x40; \
        } else { \
            t &= ~0x40; \
        } \
        if ((x & 4) != 0) { \
            t |= 0x80; \
        } else { \
            t &= ~0x80; \
        } \
        if ((x & 8) != 0) { \
            t |= 0x10; \
        } else { \
            t &= ~0x10; \
        } \
        if ((x & 0x10) != 0) { \
            t |= 0x1; \
        } else { \
            t &= ~0x1; \
        } \
        if ((x & 0x20) != 0) { \
            t |= 0x2; \
        } else { \
            t &= ~0x2; \
        } \
        if ((x & 0x40) != 0) { \
            t |= 0x8; \
        } else { \
            t &= ~0x8; \
        } \
        if ((x & 0x80) != 0) { \
            t |= 0x4; \
        } else { \
            t &= ~0x4; \
        } \
    }

int main()
{
    // cipher text
    uint8_t c0, c1, c2, c3, c4, c5, c6, c7;
    // expected result
    uint8_t k0 = {{k0}}, k1 = {{k1}}, k2 = {{k2}}, k3 = {{k3}},
            k4 = {{k4}}, k5 = {{k5}}, k6 = {{k6}}, k7 = {{k7}};
    // plain text (user input)
    uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;
    // temporary variable to hold the transformation output
    uint8_t t = 0;

    // Read input
    read(0, &p0, 1);
    read(0, &p1, 1);
    read(0, &p2, 1);
    read(0, &p3, 1);
    read(0, &p4, 1);
    read(0, &p5, 1);
    read(0, &p6, 1);
    read(0, &p7, 1);

    TRANSFORM(p0);
    c0 = t;
    TRANSFORM(p1);
    c1 = t;
    TRANSFORM(p2);
    c2 = t;
    TRANSFORM(p3);
    c3 = t;
    TRANSFORM(p4);
    c4 = t;
    TRANSFORM(p5);
    c5 = t;
    TRANSFORM(p6);
    c6 = t;
    TRANSFORM(p7);
    c7 = t;

    // printf("p0 = %d, p1 = %d, p2 = %d, p3 = %d, p4 = %d, p5 = %d, p6 = %d, p7 = %d\n", p0, p1, p2, p3, p4, p5, p6, p7);
    // printf("c0 = %d, c1 = %d, c2 = %d, c3 = %d, c4 = %d, c5 = %d, c6 = %d, c7 = %d\n", c0, c1, c2, c3, c4, c5, c6, c7);
    // printf("k0 = %d, k1 = %d, k2 = %d, k3 = %d, k4 = %d, k5 = %d, k6 = %d, k7 = %d\n", k0, k1, k2, k3, k4, k5, k6, k7);
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
