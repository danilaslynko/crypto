#include "crypto.h"
#include <string.h>

#define MESSAGE_FILE "message"
#define SIGNATURE_FILE "signature"

void generate_keypair();
void sign_message();
void check_signature();

BIGNUM *p;
BIGNUM *g;
BIGNUM *public_key;
BIGNUM *private_key;

void write_chars_to_file(const char *src, size_t length, char *file_path) {
    if (length < 0) {
        const char *src_copy_pointer = src;
        length = 0;
        while (*src_copy_pointer) {
            length++; src_copy_pointer++;
        }
    }
    FILE *file = fopen(file_path, "wb+");
    fwrite(src, length, sizeof(char), file);
    fclose(file);
}

void read_chars_from_file(char **dest, long *file_size, char *file_path) {
    FILE *file = fopen(file_path, "rb");

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    rewind(file);

    *dest = calloc(sizeof(char) * (*file_size + 1), sizeof(char));

    fread(*dest, *file_size, sizeof(char), file);

    fclose(file);
}

int main() {
    char command[10];
    while (1) {
        printf("What do you want to do? ('generate_keypair'/'sign_message'/'check_signature')\r\n");
        scanf("%s", command);
        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "generate_keypair") == 0) {
            generate_keypair();
        } else if (strcmp(command, "sign_message") == 0) {
            sign_message();
        } else if (strcmp(command, "check_signature") == 0) {
            check_signature();
        } else {
            printf("Unknown command, try again\r\n");
        }
    }

    BN_free(private_key);
    BN_free(public_key);
    BN_free(p);
    BN_free(g);

    return 0;
}

void extract_hex_from_string(char **public_key_file_content, char *hex) {
    while (**public_key_file_content) {
        if (**public_key_file_content == '\r' || **public_key_file_content == 0) {
            if (**public_key_file_content == '\r') {
                (*public_key_file_content)++;
                (*public_key_file_content)++;
            }
            break;
        }

        *hex = **public_key_file_content;
        (*public_key_file_content)++;
        hex++;
    }

    *hex = 0;
}

void sign_message() {
    unsigned char *message = calloc(32 / sizeof(char), sizeof(char));
    printf("Enter message to sign:\r\n");
    scanf("%s", message);

    BIGNUM *r, *s;
    al_gamal_sign_message(message, private_key, p, g, &r, &s);
    char *r_hex = BN_bn2hex(r);
    char *s_hex = BN_bn2hex(s);
    size_t result_size = strlen(r_hex) + 2 + strlen(s_hex) + 1;
    char *result = malloc(result_size);
    snprintf(result, result_size, "%s\r\n%s", r_hex, s_hex);
    result[result_size - 1] = 0;
    write_chars_to_file(result, result_size, SIGNATURE_FILE);
    write_chars_to_file(message, strlen(message), MESSAGE_FILE);

    BN_free(r);
    BN_free(s);
    OPENSSL_free(r_hex);
    OPENSSL_free(s_hex);
    free(result);
    free(message);
}

void check_signature() {
    unsigned char *message;
    char *signature_hex;
    long signature_length, message_length;
    read_chars_from_file(&message, &message_length, MESSAGE_FILE);
    read_chars_from_file(&signature_hex, &signature_length, SIGNATURE_FILE);

    char r_hex[97], s_hex[97];
    extract_hex_from_string(&signature_hex, r_hex);
    extract_hex_from_string(&signature_hex, s_hex);

    BIGNUM *r = BN_new(), *s = BN_new();
    BN_hex2bn(&r, r_hex);
    BN_hex2bn(&s, s_hex);

    int check_signature_result = al_gamal_check_signature(message, public_key, p, g, r, s);

    if (check_signature_result)
        printf("Signature is valid! Message is:\r\n%s\r\nIt was signed with signature:\r\nr: %s\r\ns: %s\r\n", message, r_hex, s_hex);
    else
        printf("Signature is invalid.\r\n");

    free(message);
    BN_free(r);
    BN_free(s);
}

void generate_keypair() {
    generate_al_gamal_parameters(&g, &p, &private_key, &public_key);

    char *p_hex = BN_bn2hex(p);
    char *g_hex = BN_bn2hex(g);
    char *public_key_hex = BN_bn2hex(public_key);
    char *private_key_hex = BN_bn2hex(private_key);

    printf("P-parameter: %s,\r\nG-parameter: %s,\r\nprivate key: %s,\r\npublic key: %s\r\n", p_hex, g_hex, private_key_hex, public_key_hex);

    OPENSSL_free(p_hex);
    OPENSSL_free(g_hex);
    OPENSSL_free(private_key_hex);
    OPENSSL_free(public_key_hex);
}
