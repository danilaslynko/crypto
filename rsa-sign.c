#include "crypto.h"
#include <string.h>

#define MESSAGE_FILE "message"
#define SIGNATURE_FILE "signature"

void generate_keypair();
void sign_message();
void check_signature();

BIGNUM *modulus;
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
    BN_free(modulus);

    return 0;
}

void sign_message() {
    char *message = calloc(BN_num_bits(modulus) / sizeof(char), sizeof(char));
    printf("Enter message to sign:\r\n");
    scanf("%s", message);

    BIGNUM *signature = rsa_sign_message(message, private_key, modulus);
    char *signature_hex = BN_bn2hex(signature);
    write_chars_to_file(signature_hex, strlen(signature_hex), SIGNATURE_FILE);
    write_chars_to_file(message, strlen(message), MESSAGE_FILE);

    BN_free(signature);
    OPENSSL_free(signature_hex);
    free(message);
}

void check_signature() {
    char *message, *signature_hex;
    long signature_length, message_length;
    read_chars_from_file(&message, &message_length, MESSAGE_FILE);
    read_chars_from_file(&signature_hex, &signature_length, SIGNATURE_FILE);

    BIGNUM *signature = BN_new();
    BN_hex2bn(&signature, signature_hex);

    int check_signature_result = rsa_check_signature(message, signature, public_key, modulus);

    if (check_signature_result)
        printf("Signature is valid! Message is:\r\n%s\r\nIt was signed with signature:\r\n%s\r\n", message, signature_hex);
    else
        printf("Signature is invalid.\r\n");

    free(message);
    free(signature_hex);
    BN_free(signature);
}

void generate_keypair() {
    generate_rsa_keys(&modulus, &private_key, &public_key);

    char *modulus_hex = BN_bn2hex(modulus);
    char *public_key_hex = BN_bn2hex(public_key);
    char *private_key_hex = BN_bn2hex(private_key);

    size_t result_size = strlen(public_key_hex) + 2 + strlen(modulus_hex) + 1;
    char result[result_size];
    snprintf(result, result_size, "%s\r\n%s", public_key_hex, modulus_hex);
    printf("Modulus: %s,\r\nprivate key: %s,\r\npublic key: %s\r\n", modulus_hex, private_key_hex, public_key_hex);

    OPENSSL_free(modulus_hex);
    OPENSSL_free(private_key_hex);
    OPENSSL_free(public_key_hex);
}
