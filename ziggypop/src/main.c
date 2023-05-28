#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define INPUT_SIZE 128
#define ALARM_SECONDS 30

void be_a_ctf_challenge() {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(ALARM_SECONDS);
}


void rot13(char * s) {
    unsigned int i;
    unsigned int len_s = strlen(s);
    for (i = 0; i < len_s; i++) {
        if ((s[i] >= 0x41) && (s[i] <= 0x5a)) {
            s[i] += 13;
            if (s[i] > 0x5a) {
                s[i] -= 26;
            }
        }
        if ((s[i] >= 0x61) && (s[i] <= 0x7a)) {
            s[i] += 13;
            if ((unsigned char) s[i] > 0x7a) {
                s[i] -= 26;
            }
        }
    }
}


int main() {
    be_a_ctf_challenge();

    puts("Hello challenger, enter your payload below:");

    char input[INPUT_SIZE];

    fgets(input, INPUT_SIZE, stdin);
    rot13(input);

    return system(input);
}
