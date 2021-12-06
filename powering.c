#include <stdio.h>
#include <conio.h>
#include "custom_math.h"

#define PARAMETERS_LESSER_THEN_NULL 1

int main() {
    long a, x, p;

    printf("Input 'a' parameter:");
    scanf("%ld", &a);
    printf("Input 'x' parameter:");
    scanf("%ld", &x);
    printf("Input 'p' parameter:");
    scanf("%ld", &p);

    if (a <= 0 || x <= 0 || p <= 0)
        return PARAMETERS_LESSER_THEN_NULL;

    printf("Left to right powering result: %ld\r\n", left_to_right_power(a, x, p));
    printf("Right to left powering result: %ld\r\n", right_to_left_power(a, x, p));
    printf("Native functions result: %ld\r\n", ((long) powl(a, x) % p));
    printf("Press any KEY to continue...");

    getch();
    return 0;
}
