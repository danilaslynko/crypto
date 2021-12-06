#include <stdlib.h>
#include <math.h>
#include "gsl-2.7.1/linalg/gsl_linalg.h"
#include "gsl-2.7.1/vector/gsl_vector.h"
#include "gsl-2.7.1/matrix/gsl_matrix.h"

#ifndef CRYPTO_C_CUSTOM_MATH_H
#define CRYPTO_C_CUSTOM_MATH_H

#endif //CRYPTO_C_CUSTOM_MATH_H

void to_binary_array(long number, int *buffer, int buffer_length);
long left_to_right_power(long a, long x, long p);
long right_to_left_power(long a, long x, long p);
long extended_euclid_algo(long a, long b, long *x, long *y);

void to_binary_array(long number, int *buffer, int buffer_length) {
    int current_pos = buffer_length - 1;

    while (number >= 2) {
        int remainder = number % 2;
        buffer[current_pos] = remainder;
        number /= 2;
        current_pos--;
    }

    buffer[0] = number;
}

long left_to_right_power(long a, long x, long p) {
    int string_length = (int) log2(x) + 1;
    int binary[string_length];
    to_binary_array(x, binary, string_length);

    long result = 1;

    for (int i = string_length - 1; i >= 0; --i) {
        result = (result * result) % p;
        if (binary[i]) {
            result = (result * a) % p;
        }
    }

    return result;
}

long right_to_left_power(long a, long x, long p) {
    int string_length = (int) log2(x) + 1;
    int binary[string_length];
    to_binary_array(x, binary, string_length);

    long result = 1;
    long s = a;

    for (int i = 0; i < string_length; i++) {
        if (binary[i]) {
            result = (result * s) % p;
        }
        s = (s * s) % p;
    }

    return result;
}

/**
 * ax + by = gcd
 * @param a greater parameter
 * @param b lesser parameter
 * @param x coefficient near a
 * @param y coefficient near b
 * @return gcd
 */
long extended_euclid_algo(long a, long b, long *x, long *y) {
    if (a == 0) {
        *x = 0;
        *y = 1;
        return b;
    }

    long x1, y1;
    long gcd = extended_euclid_algo(b % a, a, &x1, &y1);

    *x = y1 - (b / a) * x1;
    *y = x1;

    return gcd;
}

unsigned long long int power(unsigned long long int base, unsigned long long int exp, unsigned long long int modulo) {
    unsigned long long int i, result = 1;
    for (i = 0; i < exp; i++)
        result = (result * base) % modulo;
    return result;
}

unsigned long long int baby_step_giant_step(unsigned long long int a, unsigned long long int b, unsigned long long int p) {
    if (a <= 0 || b <= 0 || p <= 0)
        return 0;

    unsigned long long int m = sqrtl(p) + 1l, k = m;
    unsigned long long int a_im[k];
    unsigned long long int ba_j[m];
    for (unsigned long long int i = 1; i <= k; i++) {
        a_im[i - 1l] = power(a, i * m, p);
        ba_j[i - 1l] = (b * power(a, i, p)) % p;
    }

    unsigned long long int result = LONG_LONG_MAX;
    for (unsigned long long int j = 0; j < k; j++) {
        for (unsigned long long int i = 0; i < m; i++) {
            if (a_im[i] == ba_j[j]) {
                unsigned long long int intermediary_result = ((i + 1l) * m - j - 1l) % p;
                if (intermediary_result < result) result = intermediary_result;
            }
        }
    }

    return result;
}

typedef struct {
    unsigned long long **data;
    unsigned int rows;
    unsigned int columns;
} MATRIX;

MATRIX *solve_gaussian_elimination(MATRIX *input) {
    MATRIX *output = malloc(sizeof(*output));
    output->rows = 1l;
    output->columns = input->columns - 1l;
    for (unsigned int i = 0; i < input->rows; i++) {
        unsigned long long *row = input->data[i];
        for (unsigned int j = 0; j < input->columns; j++) {
            unsigned long long element_i_j = row[j];
        }
    }
}

unsigned long long index_calculus(unsigned long long int a, unsigned long long int b, unsigned long long int p) {

}
