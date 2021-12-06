//
// Created by Legion on 28.11.2021.
//
#include <stdio.h>
#include "crypto.h"
#include <conio.h>

int main() {
    unsigned char input[256];
    printf("Enter text for hashing:\r\n");
    gets(input);
    BIGNUM *hash = hash_sha256(input);
    char *hash_hex = BN_bn2hex(hash);
    printf("Hashing result:\r\n%s\r\nPress any key to exit.", hash_hex);
    getch();
    BN_free(hash);
    OPENSSL_free(hash_hex);
    return 0;
}