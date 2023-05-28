// simple simple simple: ROT-13

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


int main()
{
    // cipher text
    uint8_t c0, c1, c2, c3, c4, c5, c6, c7;
    // expected result
    uint8_t k0 = {{k0}}, k1 = {{k1}}, k2 = {{k2}}, k3 = {{k3}},
            k4 = {{k4}}, k5 = {{k5}}, k6 = {{k6}}, k7 = {{k7}};
    // plain text (user input)
    uint64_t p0 = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, p6 = 0, p7 = 0;

    uint8_t table[256] = {0};
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = 0;
    }
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = 1;
    }
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = 2;
    }
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = i + 1;
    }
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = i + 2;
    }
    for (uint32_t i = 0; i < 256; ++i) {
        table[i] = i + 13;
    }

    // Read input
    read(0, &p0, 1);
    read(0, &p1, 1);
    read(0, &p2, 1);
    read(0, &p3, 1);
    read(0, &p4, 1);
    read(0, &p5, 1);
    read(0, &p6, 1);
    read(0, &p7, 1);

    c0 = table[p0];
    c1 = table[p1];
    c2 = table[p2];
    c3 = table[p3];
    c4 = table[p4];
    c5 = table[p5];
    c6 = table[p6];
    c7 = table[p7];

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
