#ifndef CRYPTO_C_CRYPTO_H
#define CRYPTO_C_CRYPTO_H
#define PRIVATE_KEY_BIT_LENGTH 384
#define PUBLIC_KEY_BIT_LENGTH 384
#define RSA_OPEN_EXPONENT 65537

//struct bignum_st {
//    unsigned long long *d;    /* Pointer to an array of 'BN_BITS2' bit chunks. */
//    int top;    /* Index of last used d +1. */
//    /* The next are internal book keeping for bn_expand. */
//    int dmax;   /* Size of the d array. */
//    int neg;    /* one if the number is negative */
//    int flags;
//}; // WSL can't see this struct on compile stage, so we declare it explicitly

#include <openssl/bn.h>
#include <string.h>

typedef struct {
    BIGNUM *private_key;
    BIGNUM *public_key;
} KEY_PAIR;

typedef struct {
    BIGNUM *p;
    BIGNUM *g;
} KEY_PARAMS;

struct _SHA256_CTX {
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    unsigned int f;
    unsigned int g;
    unsigned int e;
    unsigned int h;
};

typedef struct _SHA256_CTX SHA256_CTX;

BIGNUM *extended_euclid_algo(const BIGNUM *a, const BIGNUM *b, BIGNUM **x, BIGNUM **y, BN_CTX *ctx);

BIGNUM *inverse_number_by_modulus(BIGNUM *a, BIGNUM *p);

unsigned char *prepare_input_data(const unsigned char *input, unsigned long *result_size);

void init_ctx(SHA256_CTX *ctx);

void diffie_hellman_generate_params(KEY_PARAMS *params) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *q = BN_new();
    BN_generate_prime_ex(q, PUBLIC_KEY_BIT_LENGTH, 1, NULL, NULL, NULL);

    params->p = BN_new();

    BIGNUM *double_q = BN_new();
    BN_copy(double_q, q);
    BN_mul_word(double_q, 2);
    BN_copy(params->p, double_q);
    BN_add_word(params->p, 1);

    params->g = BN_new();
    BN_one(params->g);

    BIGNUM *g_exp = BN_new();
    BN_one(g_exp);

    while (BN_cmp(params->p, params->g) && BN_is_one(g_exp)) {
        BN_add_word(params->g, 1);
        BN_mod_exp(g_exp, params->g, q, params->p, ctx);
    }

    BN_free(q);
    BN_free(g_exp);
    BN_free(double_q);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void diffie_hellman_generate_key_pair(KEY_PARAMS *params, KEY_PAIR *key_pair) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    key_pair->private_key = BN_new();
    BN_rand(key_pair->private_key, PRIVATE_KEY_BIT_LENGTH, 1, 1);

    key_pair->public_key = BN_new();
    BN_mod_exp(key_pair->public_key, params->g, key_pair->private_key, params->p, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void diffie_hellman_compute_secret(BIGNUM *private_a, BIGNUM *public_b, BIGNUM *p, BIGNUM *secret) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BN_mod_exp(secret, public_b, private_a, p, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

BIGNUM *generate_big_prime() {
    BIGNUM *q = BN_new();
    BN_generate_prime_ex(q, PUBLIC_KEY_BIT_LENGTH, 1, NULL, NULL, NULL);

    return q;
}

void shamir_generate_secret_data(BIGNUM *p, BIGNUM **first, BIGNUM **second) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *q = BN_new();
    BN_generate_prime_ex(q, PUBLIC_KEY_BIT_LENGTH / 2, 0, NULL, NULL, NULL);

    if (!BN_is_odd(q)) BN_add_word(q, 1);

    BIGNUM *diminished_p = BN_new();
    BN_copy(diminished_p, p);
    BN_sub_word(diminished_p, 1);

    BIGNUM *inverse = BN_mod_inverse(NULL, q, diminished_p, ctx);
    while (inverse == NULL && BN_cmp(p, q) == 1) {
        BN_add_word(q, 2);
        inverse = BN_mod_inverse(NULL, q, diminished_p, ctx);
    }

    *first = q;
    *second = inverse;
}

BIGNUM *shamir_exp(BIGNUM *data, BIGNUM *secret, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *result = BN_new();
    BN_mod_exp(result, data, secret, p, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return result;
}

BIGNUM *extended_euclid_algo(const BIGNUM *a, const BIGNUM *b, BIGNUM **x, BIGNUM **y, BN_CTX *ctx) {
    if (BN_is_zero(a)) {
        *x = BN_new();
        BN_one(*x);

        *y = BN_new();
        BN_zero(*y);

        BIGNUM *gcd = BN_new();
        BN_copy(gcd, b);
        return gcd;
    }

    BIGNUM *x1, *y1;

    BIGNUM *remainder = BN_new(), *div_result = BN_new();
    BN_div(div_result, remainder, b, a, ctx);

    BIGNUM *gcd = extended_euclid_algo(remainder, a, &x1, &y1, ctx);

    BIGNUM *multiply_res = BN_new();
    BN_mul(multiply_res, div_result, x1, ctx);
    *x = BN_new();
    BN_sub(*x, y1, multiply_res);
    *y = x1;

    BN_free(remainder);
    BN_free(div_result);

    return gcd;
}

BIGNUM *inverse_number_by_modulus(BIGNUM *a, BIGNUM *p) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *x, *y;
    BIGNUM *gcd = extended_euclid_algo(a, p, &x, &y, ctx);

    if (!BN_is_one(gcd)) return NULL;

    if (BN_is_negative(x)) {
        BIGNUM *result = BN_new();
        BN_add(result, p, x);
        BN_copy(x, result);
    }

    BIGNUM *inverse = BN_new();
    BN_mod_inverse(inverse, a, p, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return x;
}

/**
 * @param p prime number
 * @param safe if 1, p is guaranteed to be 2q+1, where q is prime
 * @return primary root
 */
BIGNUM *al_gamal_find_primary_root(BIGNUM *p, int safe) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *psi = BN_new();
    BN_copy(psi, p);
    BN_sub_word(psi, 1);
    BIGNUM **fact;
    int fact_number;

    if (safe == 1) {
        fact_number = 2;
        fact = malloc(fact_number * sizeof(fact));
        *fact = BN_new();
        BN_set_word(*fact, 2);
        fact++;
        BIGNUM *q = BN_new();
        BN_copy(q, psi);
        BN_sub_word(q, 2);
        *fact = q;
        fact--;
    } else {
        // мне так впадлу реализовывать факторизацию в общем случае, здесь все равно всегда будет safe-число
    }

    BIGNUM *result = BN_new();
    BN_set_word(result, 2);
    while (BN_cmp(p, result) == 1) {
        int is_primary_root = 1;

        for (int i = 0; i < fact_number; i++, fact++) {
            BIGNUM *exp = BN_new();
            BN_mod_exp(exp, result, *fact, p, ctx);
            is_primary_root &= !BN_is_one(exp);
        }

        if (is_primary_root) {
            fact -= fact_number;
            break;
        }

        BN_add_word(result, 1);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_free(psi);
    for (int i = 0; i < fact_number; i++) {
        BN_free(*fact++);
    }

    return result;
}

void al_gamal_encrypt_data(BIGNUM **a, BIGNUM **b,
                           BIGNUM *data,
                           BIGNUM *g, BIGNUM *k, BIGNUM *p, BIGNUM *y) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BN_mod_exp(*a, g, k, p, ctx);

    BIGNUM *_b = BN_new();
    BN_mod_exp(_b, y, k, p, ctx);
    BN_mod_mul(*b, data, _b, p, ctx);

    BN_free(_b);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void al_gamal_decrypt_data(unsigned char **decrypted, size_t *decrypted_size,
                           BIGNUM *a, BIGNUM *b,
                           BIGNUM *p, BIGNUM *x) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *result = BN_new();
    BIGNUM *exponent = BN_new();
    BN_sub(exponent, p, x);
    BN_sub_word(exponent, 1);
    BIGNUM *_a = BN_new();
    BN_mod_exp(_a, a, exponent, p, ctx);
    BN_mod_mul(result, _a, b, p, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    int result_bits = BN_num_bits(result);
    *decrypted_size = result_bits / (8 * sizeof(char)) + (result_bits % (8 * sizeof(char)) ? 2 : 1);
    *decrypted = malloc(*decrypted_size);

    BN_bn2bin(result, *decrypted);
    *decrypted[*decrypted_size - 1] = 0;

    BN_free(result);
    BN_free(exponent);
    BN_free(_a);
}

void generate_rsa_keys(BIGNUM **modulus, BIGNUM **private_key, BIGNUM **public_key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = generate_big_prime();
    BIGNUM *q = generate_big_prime();
    *modulus = BN_new();
    BN_mul(*modulus, p, q, ctx);

    BN_sub_word(p, 1);
    BN_sub_word(q, 1);
    BIGNUM *phi = BN_new();
    BN_mul(phi, p, q, ctx);

    *public_key = BN_new();
    BN_set_word(*public_key, RSA_OPEN_EXPONENT);

    *private_key = BN_new();
    BN_mod_inverse(*private_key, *public_key, phi, ctx);

    BN_free(p);
    BN_free(q);
    BN_free(phi);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void generate_al_gamal_parameters(BIGNUM **g, BIGNUM **p, BIGNUM **private_key, BIGNUM **public_key) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    *p = generate_big_prime();
    *g = al_gamal_find_primary_root(*p, 1);

    *private_key = BN_new();
    BN_rand(*private_key, BN_num_bits(*p) / 2, 1, 1);

    *public_key = BN_new();
    BN_mod_exp(*public_key, *g, *private_key, *p, ctx);
}

void rsa_encrypt_data(const unsigned char *input, size_t input_size, BIGNUM *encrypted, BIGNUM *public_key, BIGNUM *modulus)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *data = BN_new();
    BN_bin2bn(input, input_size, data);
    BN_mod_exp(encrypted, data, public_key, modulus, ctx);

    BN_free(data);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void rsa_decrypt_data(unsigned char **result, BIGNUM *encrypted, BIGNUM *private_key, BIGNUM *modulus) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *decrypted = BN_new();
    BN_mod_exp(decrypted, encrypted, private_key, modulus, ctx);

    int result_bits = BN_num_bits(decrypted);
    size_t decrypted_size = result_bits / (8 * sizeof(char)) + (result_bits % (8 * sizeof(char)) ? 2 : 1);
    *result = malloc(decrypted_size);

    BN_bn2bin(decrypted, *result);

    BN_free(decrypted);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

BIGNUM *rsa_sign_message(char *message, BIGNUM *private_key, BIGNUM *modulus) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *data_to_sign = BN_new();
    BN_hex2bn(&data_to_sign, message);

    BIGNUM *signature = BN_new();
    BN_mod_exp(signature, data_to_sign, private_key, modulus, ctx);

    BN_free(data_to_sign);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return signature;
}

int rsa_check_signature(char *message, BIGNUM *signature, BIGNUM *public_key, BIGNUM *modulus) {
    if (signature == NULL || public_key == NULL || modulus == NULL)
        return 0;

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *data_to_sign = BN_new();
    BN_hex2bn(&data_to_sign, message);

    BIGNUM *message_preimage = BN_new();
    BN_mod_exp(message_preimage, signature, public_key, modulus, ctx);

    int check_result = BN_cmp(data_to_sign, message_preimage) == 0;

    BN_free(data_to_sign);
    BN_free(message_preimage);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return check_result;
}

#define rotr(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define h0 0x6A09E667
#define h1 0xBB67AE85
#define h2 0x3C6EF372
#define h3 0xA54FF53A
#define h4 0x510E527F
#define h5 0x9B05688C
#define h6 0x1F83D9AB
#define h7 0x5BE0CD19
static const unsigned int k[64] = { 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                                    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                                    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                                    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                                    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                                    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                                    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                                    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2 };

BIGNUM *hash_sha256(const unsigned char *input) {
    unsigned long augmented_size;
    unsigned char *augmented_data = prepare_input_data(input, &augmented_size);
    unsigned int chunks = augmented_size * 8 / 512;
    unsigned int split_data[chunks][64];
    for (int i = 0; i < chunks; i++) {
        int j = 0;
        for (; j < 16; j++) {
            int index = 16 * i + 4 * j;
            split_data[i][j] = (((unsigned int) augmented_data[index]) << 24) | (((unsigned int) augmented_data[index + 1]) << 16) |
                    (((unsigned int) augmented_data[index + 2]) << 8) | ((unsigned int) augmented_data[index + 3]);
        }
        for (; j < 64; j++) split_data[i][j] = 0;
    }

    SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
    init_ctx(ctx);

    for (int i = 0; i < chunks; i++) {
        for (int j = 16; j < 64; j++) {
            unsigned int s0 = rotr(split_data[i][j - 15], 7) ^ rotr(split_data[i][j - 15], 18) ^ (split_data[i][j - 15] >> 3);
            unsigned int s1 = rotr(split_data[i][j - 2], 17) ^ rotr(split_data[i][j - 2], 19) ^ (split_data[i][j - 2] >> 10);
            split_data[i][j] = split_data[i][j - 16] + s0 + split_data[i][j - 7] + s1;
        }
        unsigned int a = ctx->a;
        unsigned int b = ctx->b;
        unsigned int c = ctx->c;
        unsigned int d = ctx->d;
        unsigned int e = ctx->e;
        unsigned int f = ctx->f;
        unsigned int g = ctx->g;
        unsigned int h = ctx->h;
        for (int j = 0; j < 64; j++) {
            unsigned int sigma_0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            unsigned int ma = (a & b) ^ (a & c) ^ (b & c);
            unsigned int t2 = sigma_0 + ma;
            unsigned int sigma_1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            unsigned int ch = (e & f) ^ ((~e) & g);
            unsigned int t1 = h + sigma_1 + ch + k[j] + split_data[i][j];

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        ctx->a += a;
        ctx->b += b;
        ctx->c += c;
        ctx->d += d;
        ctx->e += e;
        ctx->f += f;
        ctx->g += g;
        ctx->h += h;
    }

    BIGNUM *digest = BN_new();
    unsigned char digest_bytes[32];
    for (int i = 0; i < 4; ++i) {
        digest_bytes[i]      = (ctx->a >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 4]  = (ctx->b >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 8]  = (ctx->c >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 12] = (ctx->d >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 16] = (ctx->e >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 20] = (ctx->f >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 24] = (ctx->g >> (24 - i * 8)) & 0b11111111;
        digest_bytes[i + 28] = (ctx->h >> (24 - i * 8)) & 0b11111111;
    }
    BN_bin2bn(digest_bytes, 32, digest);
    free(ctx);

    return digest;
}

void init_ctx(SHA256_CTX *ctx) {
    ctx->a = h0;
    ctx->b = h1;
    ctx->c = h2;
    ctx->d = h3;
    ctx->e = h4;
    ctx->f = h5;
    ctx->g = h6;
    ctx->h = h7;
}

unsigned char *prepare_input_data(const unsigned char *input, unsigned long *result_size) {
    size_t input_len = strlen(input);
    unsigned long long message_bit_length = input_len * 8;
    int size_length = 64;
    int nulls = 0;
    while ((message_bit_length + 1 + size_length + ++nulls) % 512);
    *result_size = (message_bit_length + 1 + size_length + nulls) / 8;
    unsigned char *augmented_data = calloc(sizeof(unsigned char) ,*result_size);
    memcpy(augmented_data, input, input_len);
    augmented_data[input_len] = 0b10000000;
    int i;
    for (i = input_len + 1; i < *result_size - 8; i++) { augmented_data[i] = 0; }
    for (; i < *result_size; i++) {
        augmented_data[i] = (message_bit_length >> (63 - i) * 8) & 0b11111111;
    }
    return augmented_data;
}

void al_gamal_sign_message(unsigned char *message, BIGNUM *private_key, BIGNUM *p, BIGNUM *g,
                           BIGNUM **r, BIGNUM **s) {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *data_to_sign = hash_sha256(message);

    BIGNUM *p_diminished = BN_new();
    BN_copy(p_diminished, p);
    BN_sub_word(p_diminished, 1);

    BIGNUM *k = BN_new();
    BN_rand(k, 256, 1, 0);
    BIGNUM *gcd = BN_new();
    BN_gcd(gcd, k, p_diminished, ctx);
    while (!BN_is_one(gcd)) {
        BN_add_word(k, 1);
        BN_gcd(gcd, k, p_diminished, ctx);
    }

    *r = BN_new();
    BN_mod_exp(*r, g, k, p, ctx);
    BIGNUM *k_inverse = BN_new();
    BN_mod_inverse(k_inverse, k, p_diminished, ctx);
    BIGNUM *xr = BN_new();
    BN_mul(xr, private_key, *r, ctx);
    BIGNUM *m_xr = BN_new();
    BN_sub(m_xr, data_to_sign, xr);
    *s = BN_new();
    BN_mod_mul(*s, m_xr, k_inverse, p_diminished, ctx);

    BN_free(k);
    BN_free(gcd);
    BN_free(p_diminished);
    BN_free(xr);
    BN_free(m_xr);
    BN_free(data_to_sign);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

int al_gamal_check_signature(unsigned char *message, BIGNUM *public_key, BIGNUM *p, BIGNUM *g, BIGNUM *r, BIGNUM *s) {
    if (p == NULL || public_key == NULL || g == NULL || s == NULL || r == NULL)
        return 0;

    BIGNUM *p_diminished = BN_new();
    BN_copy(p_diminished, p);
    BN_sub_word(p_diminished, 1);
    if (BN_is_negative(r) || BN_is_zero(r) || BN_cmp(p, r) != 1 || BN_is_negative(s) || BN_is_zero(s) || BN_cmp(p_diminished, s) != 1)
        return 0;

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *hash = hash_sha256(message);

    BIGNUM *yr = BN_new();
    BN_mod_exp(yr, public_key, r, p, ctx);
    BIGNUM *rs = BN_new();
    BN_mod_exp(rs, r, s, p, ctx);
    BIGNUM *left = BN_new();
    BN_mod_mul(left, yr, rs, p, ctx);

    BIGNUM *right = BN_new();
    BN_mod_exp(right, g, hash, p, ctx);
    
    int check_result = BN_cmp(left, right) == 0;

    BN_free(left);
    BN_free(right);
    BN_free(yr);
    BN_free(rs);
    BN_free(p_diminished);
    BN_free(hash);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return check_result;
}

#endif //CRYPTO_C_CRYPTO_H