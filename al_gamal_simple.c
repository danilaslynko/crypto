#include "crypto.h"
#include "stdio.h"

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = generate_big_prime();
    BIGNUM *g = al_gamal_find_primary_root(p, 1);

    BIGNUM *x = BN_new();
    BN_rand(x, BN_num_bits(p) / 2, 1, 1);

    BIGNUM *y = BN_new();
    BN_mod_exp(y, g, x, p, ctx);

    BIGNUM *k = BN_new();
    BN_generate_prime_ex(k, BN_num_bits(p) / 2, 1, NULL, NULL, NULL);

    unsigned char *input = "AAAA";
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *data = BN_new();
    BN_bin2bn(input, 4, data);
    BN_mod_exp(a, g, k, p, ctx);

    BIGNUM *_b = BN_new();
    BN_mod_exp(_b, y, k, p, ctx);
    BN_mod_mul(b, data, _b, p, ctx);

    BIGNUM *result = BN_new();
    BIGNUM *exponent = BN_new();
    BN_sub(exponent, p, x);
    BN_sub_word(exponent, 1);
    BIGNUM *_a = BN_new();
    BN_mod_exp(_a, a, exponent, p, ctx);
    BN_mod_mul(result, _a, b, p, ctx);

    unsigned char output[5];
    BN_bn2bin(result, output);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}