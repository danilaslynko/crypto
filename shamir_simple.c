//
// Created by Legion on 04.11.2021.
//

#include "crypto.h"

int main() {
    unsigned char input[] = "AAAA";
    BIGNUM *data = BN_new();
    BN_bin2bn(input, 4, data);

    BIGNUM *p = generate_big_prime();

    BIGNUM *alice_1, *alice_2, *bob_1, *bob_2;
    shamir_generate_secret_data(p, &alice_1, &alice_2);
    shamir_generate_secret_data(p, &bob_1, &bob_2);

    BIGNUM *first = BN_new();
    BIGNUM *second = BN_new();
    BIGNUM *third = BN_new();
    BIGNUM *fourth = BN_new();

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_init(ctx);

    BN_mod_exp(first, data, alice_1, p, ctx);
    BN_mod_exp(second, first, bob_1, p, ctx);
    BN_mod_exp(third, second, alice_2, p, ctx);
    BN_mod_exp(fourth, third, bob_2, p, ctx);

    unsigned char output[1024];
    BN_bn2bin(fourth, output);

    return 0;
}