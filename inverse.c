#include "custom_math.h"
#include <stdio.h>
#include <conio.h>

#define PARAMETERS_LESSER_THEN_NULL 1
#define NO_EXISTING_INVERSE 2

int main() {
    long a, n;

    printf("Input number:");
    scanf("%ld", &a);
    printf("Input modulo:");
    scanf("%ld", &n);

    if (a <= 0 || n <= 0)
        return PARAMETERS_LESSER_THEN_NULL;

    long x, y;
    long gcd = extended_euclid_algo(a, n, &x, &y);
    if (gcd > 1)
        return NO_EXISTING_INVERSE;

    while (x < 0) {
        x = n + x;
    }

    printf("The inverse of %ld modulo %ld is %ld\r\n", a, n, x);
    printf("Press any KEY to continue...");

    getch();
    return 0;
}