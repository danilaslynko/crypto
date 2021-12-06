//
// Created by Legion on 04.12.2021.
//

#include <stdio.h>
#include <conio.h>
#include "custom_math.h"

int main() {
    char input[20] = {0};
    printf("Enter a, b and p parameters on each line separately where a^x = b mod p for x calculation.\r\n"
           "Note, that numbers must be less then 18446744073709551615.\r\n"
           "a=");
    gets(input);
    unsigned long long a = atoll(input);
    printf("b=");
    gets(input);
    unsigned long long b = atoll(input);
    printf("p=");
    gets(input);
    unsigned long long p = atoll(input);
    unsigned long long x = baby_step_giant_step(a, b, p);

    if (x < 0)
        printf("X not found.");
    else
        printf("X calculated:\r\n%llu", x);

    printf("\r\nPress any key to exit.");
    getch();
    return 0;
}

