// reimplement libc because the builtins add way too much bloat
int getchar();
void putchar(int);
void exit(int);

void puts(char* str) {
    while (*str)
        putchar(*(str++));
}

static const int __builtin_bits_table[] = {
  0x800000, 0x400000, 0x200000, 0x100000,
  0x80000, 0x40000, 0x20000, 0x10000,
  0x8000, 0x4000, 0x2000, 0x1000,
  0x800, 0x400, 0x200, 0x100,
  0x80, 0x40, 0x20, 0x10,
  0x8, 0x4, 0x2, 0x1,
};
#define __BUILTIN_TO_BIT(v, t) (v >= t ? (v -= t, 1) : 0)

static unsigned int __builtin_xor(unsigned int a, unsigned int b) {
  int r = 0;
  for (int i = 0; i < 24; i++) {
    int t = __builtin_bits_table[i];
    int a1 = __BUILTIN_TO_BIT(a, t);
    int b1 = __BUILTIN_TO_BIT(b, t);
    if (a1 != b1)
      r += t;
  }
  return r;
}

// side channel friendly :)
int abs(int x) {
    if (x > 0) {
        return x; // 0 + x
    } else {
        return 0 - x; // 0 - x
    }
}

int check_flag(char* buffer) {
    if (getchar() != 'f'
        || getchar() != 'l'
        || getchar() != 'a'
        || getchar() != 'g'
        || getchar() != '{') {
        return 0;
    }

    // vmprotect?_where_we_re_going_we_ll_need_protecti0n_FR0Mm_th3_vms

    // getchar count obviously leaks these
    if (getchar() != 'v') { return 0; }
    if (getchar() != 'm') { return 0; }
    if (getchar() != 'p') { return 0; }
    if (getchar() != 'r') { return 0; }
    if (getchar() != 'o') { return 0; }
    if (getchar() != 't') { return 0; }
    if (getchar() != 'e') { return 0; }
    if (getchar() != 'c') { return 0; }
    if (getchar() != 't') { return 0; }
    if (getchar() != '?') { return 0; }
    if (getchar() != '_') { return 0; }
    if (getchar() != 'w') { return 0; }
    if (getchar() != 'h') { return 0; }
    if (getchar() != 'e') { return 0; }
    if (getchar() != 'r') { return 0; }
    if (getchar() != 'e') { return 0; }

    int result = 0;
    // Instruction count also leaks these
    result += abs(getchar() - '_');
    result += abs(getchar() - 'w');
    result += abs(getchar() - 'e');
    result += abs(getchar() - '_');
    result += abs(getchar() - 'r');
    result += abs(getchar() - 'e');
    result += abs(getchar() - '_');
    result += abs(getchar() - 'g');
    result += abs(getchar() - 'o');
    result += abs(getchar() - 'i');
    result += abs(getchar() - 'n');
    result += abs(getchar() - 'g');
    result += abs(getchar() - '_');
    result += abs(getchar() - 'w');
    result += abs(getchar() - 'e');
    result += abs(getchar() - '_');
    if (result != 0) { return 0; }

    // No instruction count side channel anymore (xor adds a bunch of noise)
    // You can leak these from the DSO by looking for CD?4 and every couple
    // ?-bytes is the right char (every 3).
    // C / 67 -> OP_POP_STK (end of previous instruction)
    // D / 68 -> OP_LOADIMMED_UINT
    // ?      -> <char of flag>
    // 4 / 52 -> OP_SAVE_LOCAL_VAR_UINT
    result += (getchar() ^ 'l');
    result += (getchar() ^ 'l');
    result += (getchar() ^ '_');
    result += (getchar() ^ 'n');
    result += (getchar() ^ 'e');
    result += (getchar() ^ 'e');
    result += (getchar() ^ 'd');
    result += (getchar() ^ '_');
    result += (getchar() ^ 'p');
    result += (getchar() ^ 'r');
    result += (getchar() ^ 'o');
    result += (getchar() ^ 't');
    result += (getchar() ^ 'e');
    result += (getchar() ^ 'c');
    result += (getchar() ^ 't');
    result += (getchar() ^ 'i');
    if (result != 0) { return 0; }

    // ok THIS section you can't side channel like that
    // CD\xff????4 will leak the constants at the end if you know to look for them
    // But you'll probably have to write an actual disassembler for this part
    // Apologies in advance lol

    // Probably only has 1 solution, at least for integers in 32..127
    int a = getchar();
    int b = getchar();
    int c = getchar();
    int d = getchar();
    int e = getchar();
    int f = getchar();
    int g = getchar();
    int h = getchar();
    int i = getchar();
    int j = getchar();
    int k = getchar();
    int l = getchar();
    int m = getchar();
    int n = getchar();
    int o = getchar();
    int p = getchar();
    // Thanks, python
    // Busted by subtraction: apparently "s0n_FR0Mm_3ht_mv" also matches if you forget abs()
    int result2[16] = { 0 };
    result2[0] = abs(a + b + c + d + e + f + g + h + i + j + k + l + m + n + o - 1327);
    result2[1] = abs(b + c + d + e + f + g + h + i + j + k + l + m + n + o + p - 1394);
    result2[2] = abs(c + d + e + f + g + h + i + j + k + l + m + n + o + p + a - 1332);
    result2[3] = abs(d + e + f + g + h + i + j + k + l + m + n + o + p + a + b - 1347);
    result2[4] = abs(e + f + g + h + i + j + k + l + m + n + o + p + a + b + c - 1372);
    result2[5] = abs(f + g + h + i + j + k + l + m + n + o + p + a + b + c + d - 1360);
    result2[6] = abs(g + h + i + j + k + l + m + n + o + p + a + b + c + d + e - 1394);
    result2[7] = abs(h + i + j + k + l + m + n + o + p + a + b + c + d + e + f - 1365);
    result2[8] = abs(i + j + k + l + m + n + o + p + a + b + c + d + e + f + g - 1333);
    result2[9] = abs(j + k + l + m + n + o + p + a + b + c + d + e + f + g + h - 1347);
    result2[10] = abs(k + l + m + n + o + p + a + b + c + d + e + f + g + h + i - 1326);
    result2[11] = abs(l + m + n + o + p + a + b + c + d + e + f + g + h + i + j - 1338);
    result2[12] = abs(m + n + o + p + a + b + c + d + e + f + g + h + i + j + k - 1391);
    result2[13] = abs(n + o + p + a + b + c + d + e + f + g + h + i + j + k + l - 1347);
    result2[14] = abs(o + p + a + b + c + d + e + f + g + h + i + j + k + l + m - 1324);
    result2[15] = abs(p + a + b + c + d + e + f + g + h + i + j + k + l + m + n - 1333);

    if (result2[0] != 0) { return 0; }
    if (result2[1] != 0) { return 0; }
    if (result2[2] != 0) { return 0; }
    if (result2[3] != 0) { return 0; }
    if (result2[4] != 0) { return 0; }
    if (result2[5] != 0) { return 0; }
    if (result2[6] != 0) { return 0; }
    if (result2[7] != 0) { return 0; }
    if (result2[8] != 0) { return 0; }
    if (result2[9] != 0) { return 0; }
    if (result2[10] != 0) { return 0; }
    if (result2[11] != 0) { return 0; }
    if (result2[12] != 0) { return 0; }
    if (result2[13] != 0) { return 0; }
    if (result2[14] != 0) { return 0; }
    if (result2[15] != 0) { return 0; }

    // This section brought to you by getting woken up after 4 hours of sleep

    // Mega sanity check in a way that is hopefully not ez to leak
    // Thanks again, python
    result = 0;
    if (n - 0x3c - 0xf - 0xc - 0x10 - 0xf                        != 0) { result = 1; }
    if (l - 0x31 - 0x1 - 0x1                                     != 0) { result = 1; }
    if (a - 0x2c - 0x4                                           != 0) { result = 1; }
    if (c - 0x58 - 0x3 - 0x3 - 0x1                               != 0) { result = 1; }
    if (e - 0x24 - 0x3 - 0x13 - 0x11 - 0x3 - 0x4                 != 0) { result = 1; }
    if (f - 0xe - 0x10 - 0xe - 0x1 - 0x3                         != 0) { result = 1; }
    if (p - 0x8 - 0x2b - 0xb - 0x1b - 0x1a                       != 0) { result = 1; }
    if (g - 0x3f - 0x4 - 0x6 - 0x4                               != 0) { result = 1; }
    if (i - 0x5a - 0x1 - 0x1 - 0x3                               != 0) { result = 1; }
    if (d - 0x39 - 0xa - 0x3                                     != 0) { result = 1; }
    if (j - 0x37 - 0x20 - 0xf - 0x5 - 0x7 - 0x1 - 0x1            != 0) { result = 1; }
    if (m - 0x14 - 0x4b                                          != 0) { result = 1; }
    if (h - 0x3d - 0x5 - 0xd - 0x4 - 0x2 - 0xa - 0x5 - 0x8 - 0x1 != 0) { result = 1; }
    if (k - 0x35 - 0x1c - 0x17                                   != 0) { result = 1; }
    if (o - 0x34 - 0x25 - 0x10 - 0x2 - 0x2                       != 0) { result = 1; }
    if (b - 0x2f - 0x17 - 0x11 - 0x3 - 0x12 - 0x1 - 0x1          != 0) { result = 1; }

    if (result == 1) {
        return 0;
    }

    if (getchar() != '}') {
        return 0;
    }

    return 1;
}

int main() {
    char buffer[0x80];

    puts("What is the flag?\n");

    if (check_flag(buffer)) {
        puts("Yes! That's it!\n");
    } else {
        puts("No, that's not it!\n");
    }
    return 0;
}