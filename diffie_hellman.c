#include "crypto.h"
#include <string.h>

void generate_keypair();
void calculate_secret();

void write_chars_to_file(const char *src, int length) {
    if (length < 0) {
        const char *src_copy_pointer = src;
        length = 0;
        while (*src_copy_pointer) {
            length++; src_copy_pointer++;
        }
    }
    char file_path[256];
    scanf("%s", file_path);
    FILE *file = fopen(file_path, "wb+");
    fwrite(src, length, sizeof(char), file);
    fclose(file);
}

void read_chars_from_file(char **dest, long *file_size) {
    char file_path[256];
    scanf("%s", file_path);
    FILE *props_file = fopen(file_path, "rb");

    fseek(props_file, 0, SEEK_END);
    *file_size = ftell(props_file);
    rewind(props_file);

    *dest = malloc(sizeof(char) * (*file_size + 1));

    fread(*dest, *file_size, sizeof(char), props_file);

    fclose(props_file);
}

int main() {
    char command[10];
    while (1) {
        printf("What do you want to do? ('generate_keypair'/'calculate_secret'/'exit')\r\n");
        scanf("%s", command);
        if (strcmp(command, "exit") == 0) {
            break;
        } else if (strcmp(command, "generate_keypair") == 0) {
            generate_keypair();
        } else if (strcmp(command, "calculate_secret") == 0) {
            calculate_secret();
        } else {
            printf("Unknown command, try again\r\n");
        }
    }

    return 0;
}

void calculate_secret() {
    BIGNUM *private_own, *public_opposite, *p;

    printf("Enter your private key file name:\r\n");
    char *buffer;
    long file_length;
    read_chars_from_file(&buffer, &file_length);
    private_own = BN_new();
    BN_hex2bn(&private_own, buffer);
    free(buffer);

    printf("Enter opponent's public key file name:\r\n");
    read_chars_from_file(&buffer, &file_length);
    public_opposite = BN_new();
    BN_hex2bn(&public_opposite, buffer);
    free(buffer);

    printf("Enter path to file with parameter 'p':\r\n");
    read_chars_from_file(&buffer, &file_length);
    p = BN_new();
    BN_hex2bn(&p, buffer);
    free(buffer);

    BIGNUM *secret = BN_new();
    diffie_hellman_compute_secret(private_own, public_opposite, p, secret);

    printf("Enter file name for secret:\r\n");

    char *hex = BN_bn2hex(secret);
    write_chars_to_file(hex, -1);
    OPENSSL_free(hex);

    BN_free(p);
    BN_free(private_own);
    BN_free(public_opposite);
    BN_free(secret);
}

void generate_keypair() {
    char params_mode[10];
    KEY_PARAMS *params;

    while (1) {
        printf("Enter parameters mode:\r\n('generate' - new 'g' and 'p' will be generated, "
               "'existing' - you need to provide file with 'g' and 'p')\r\n");
        scanf("%s", params_mode);

        if (strcmp(params_mode, "generate") == 0) {
            params = malloc(sizeof(*params));
            diffie_hellman_generate_params(params);

            printf("Enter file name for 'g' property:\r\n");
            char *hex = BN_bn2hex(params->g);
            write_chars_to_file(hex, -1);
            OPENSSL_free(hex);
            printf("Enter file name for 'p' property:\r\n");
            hex = BN_bn2hex(params->p);
            write_chars_to_file(hex, -1);
            OPENSSL_free(hex);

            break;
        } else if (strcmp(params_mode, "existing") == 0) {
            long g_size, p_size;
            char *g, *p;

            printf("Enter path to file with parameter 'g':\r\n");
            read_chars_from_file(&g, &g_size);
            printf("Enter path to file with parameter 'p':\r\n");
            read_chars_from_file(&p, &p_size);

            params = malloc(sizeof(KEY_PARAMS));
            params->g = BN_new();
            params->p = BN_new();
            BN_hex2bn(&params->g, g);
            BN_hex2bn(&params->p, p);

            free(g);
            free(p);

            break;
        }

        printf("Unrecognized option '%s', try again\r\n", params_mode);
    }

    KEY_PAIR *key_pair = malloc(sizeof (*key_pair));
    key_pair->public_key = BN_new();
    key_pair->private_key = BN_new();
    diffie_hellman_generate_key_pair(params, key_pair);

    printf("Enter private key file name for saving:\r\n");
    char *key_hex = BN_bn2hex(key_pair->private_key);
    write_chars_to_file(key_hex, -1);
    OPENSSL_free(key_hex);
    printf("Enter public key file name for saving:\r\n");
    key_hex = BN_bn2hex(key_pair->public_key);
    write_chars_to_file(key_hex, -1);
    OPENSSL_free(key_hex);

    BN_free(params->g);
    BN_free(params->p);
    BN_free(key_pair->private_key);
    BN_free(key_pair->public_key);
    free(key_pair);
    free(params);
}
