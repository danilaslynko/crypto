#include "crypto.h"

#define OPEN_EXPONENT 65537

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = generate_big_prime();
    BIGNUM *q = generate_big_prime();

    BIGNUM *n = BN_new();
    BN_mul(n, p, q, ctx);

    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BIGNUM *phi = BN_new();
    BN_mul(phi, p, q, ctx);

    BIGNUM *e = BN_new();
    BN_set_word(e, OPEN_EXPONENT);

    BIGNUM *d = BN_new();
    BN_mod_inverse(d, e, phi, ctx);

    unsigned char *input = "AAAA";
    BIGNUM *enc = BN_new();
    BIGNUM *data = BN_new();
    BN_bin2bn(input, 4, data);
    BN_mod_exp(enc, data, e, n, ctx);

    BIGNUM *dec = BN_new();
    BN_mod_exp(dec, enc, d, n, ctx);

    unsigned char output[5];
    BN_bn2bin(dec, output);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}