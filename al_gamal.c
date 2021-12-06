#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <conio.h>
#include "crypto.h"
#define PUBLIC_KEY_FILE_NAME "public.key"
#define ENCRYPTED_FILE_NAME "encrypted"

#define SENDER_LOCK "sender_lock"
#define RECEIVER_LOCK "receiver_lock"

#define UNKNOWN_MODE 1
#define UNABLE_TO_BECOME_SENDER 2
#define UNABLE_TO_BECOME_RECEIVER 3

typedef enum {
    INITIALIZE_PARAMETERS,
    WAIT_FOR_DATA,
    ENCRYPT_BY_SENDER,
    DECRYPT_BY_RECEIVER,
    TERMINATE
} STAGE;

typedef enum {
    SENDER, RECEIVER
} MODE;

STAGE stage;

BIGNUM *p;
BIGNUM *y;
BIGNUM *g;
BIGNUM *x; // only for receiver
BIGNUM *k; // only for sender

void start_listen(MODE mode);
void listen_sender();
void listen_receiver();
void init_sender();
void init_receiver();

void init(MODE mode);

void extract_hex_from_string(char **public_key_file_content, char *hex);

void read_chars_from_file(char **dest, long *file_size, const char *file_path) {
    FILE *props_file = fopen(file_path, "rb");

    fseek(props_file, 0, SEEK_END);
    *file_size = ftell(props_file);
    rewind(props_file);

    *dest = malloc(sizeof(unsigned char) * (*file_size + 1));

    fread(*dest, *file_size, sizeof(char), props_file);

    fclose(props_file);
}

void write_chars_to_file(const char *src, unsigned long long length, const char *file_path) {
    if (length < 0) length = strlen(src);
    FILE *file = fopen(file_path, "wb+");
    fwrite(src, length, sizeof(char), file);
    fclose(file);
}

int main() {
    char mode_str[9];
    MODE mode;
    FILE *lock;

    printf("Are you 'SENDER' or 'RECEIVER'?\r\n");
    scanf("%s", mode_str);
    if (strcmp("SENDER", mode_str) == 0) {
        mode = SENDER;
        if (access(SENDER_LOCK, F_OK) == 0) {
            printf("There is already sender defined\r\n");
            getch();
            return UNABLE_TO_BECOME_SENDER;
        }
        lock = fopen(SENDER_LOCK, "w+");
    } else if (strcmp("RECEIVER", mode_str) == 0) {
        mode = RECEIVER;
        if (access(RECEIVER_LOCK, F_OK) == 0) {
            printf("There is already receiver defined\r\n");
            getch();
            return UNABLE_TO_BECOME_RECEIVER;
        }
        lock = fopen(RECEIVER_LOCK, "w+");
    } else {
        printf("Unknown application mode, exiting");
        getch();
        return UNKNOWN_MODE;
    }

    init(mode);
    start_listen(mode);

    getch();
    fclose(lock);
    if (mode == SENDER) {
        remove(ENCRYPTED_FILE_NAME);
        remove(SENDER_LOCK);
    } else {
        remove(PUBLIC_KEY_FILE_NAME);
        remove(RECEIVER_LOCK);
    }

    BN_free(p);
    BN_free(g);
    BN_free(y);
    BN_free(x);
    BN_free(k);

    return 0;
}

void init (MODE mode) {
    stage = INITIALIZE_PARAMETERS;
    if (mode == SENDER) init_sender();
    else init_receiver();
}

void init_receiver() {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    p = generate_big_prime();
    char *p_hex = BN_bn2hex(p);
    g = al_gamal_find_primary_root(p, 1);
    char *g_hex = BN_bn2hex(g);

    x = BN_new();
    BN_rand(x, BN_num_bits(p) / 2, 1, 1);

    y = BN_new();
    BN_mod_exp(y, g, x, p, ctx);
    char *y_hex = BN_bn2hex(y);

    size_t result_size = strlen(p_hex) + 2 + strlen(g_hex) + 2 + strlen(y_hex) + 1;
    char result[result_size];
    snprintf(result, result_size, "%s\r\n%s\r\n%s", p_hex, g_hex, y_hex);

    write_chars_to_file(result, result_size, PUBLIC_KEY_FILE_NAME);
}

void init_sender() {
    while (1) {
        if (access(PUBLIC_KEY_FILE_NAME, F_OK) == 0) {
            char *public_key_file_content;
            long content_length;
            read_chars_from_file(&public_key_file_content, &content_length, PUBLIC_KEY_FILE_NAME);

            char p_hex[128], g_hex[128], y_hex[128];
            extract_hex_from_string(&public_key_file_content, p_hex);
            extract_hex_from_string(&public_key_file_content, g_hex);
            extract_hex_from_string(&public_key_file_content, y_hex);

            g = BN_new(), p = BN_new(), y = BN_new();
            BN_hex2bn(&g, g_hex);
            BN_hex2bn(&p, p_hex);
            BN_hex2bn(&y, y_hex);

            k = BN_new();
            BN_generate_prime_ex(k, BN_num_bits(p) / 2, 1, NULL, NULL, NULL);

            break;
        }

        sleep(1);
    }
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

void start_listen(MODE mode) {
    stage = WAIT_FOR_DATA;
    if (mode == SENDER) listen_sender();
    else listen_receiver();
}

void listen_receiver() {
    while(1) {
        if (stage == WAIT_FOR_DATA) {
            if (access(ENCRYPTED_FILE_NAME, F_OK) == 0) {
                stage = DECRYPT_BY_RECEIVER;

                char *encrypted_data;
                long file_length;
                read_chars_from_file(&encrypted_data, &file_length, ENCRYPTED_FILE_NAME);

                BIGNUM *a = BN_new(), *b = BN_new();
                char a_hex[128], b_hex[128];
                extract_hex_from_string(&encrypted_data, a_hex);
                extract_hex_from_string(&encrypted_data, b_hex);
                BN_hex2bn(&a, a_hex);
                BN_hex2bn(&b, b_hex);

                unsigned char *result;
                size_t result_size;
                al_gamal_decrypt_data(&result, &result_size, a, b, p, x);

                printf("Received message:\r\n%s\r\n", result);

                free(result);
                BN_free(a);
                BN_free(b);

                stage = TERMINATE;
            }
        } else if (stage == TERMINATE) {
            printf("Exchange by receiver side finished.\r\n");
            break;
        }

        sleep(1);
    }
}

void listen_sender() {
    if (stage == WAIT_FOR_DATA) {
        unsigned char input[1024];
        printf("Enter input and press ENTER to start exchange:\r\n");
        scanf("%s", input);

        stage = ENCRYPT_BY_SENDER;
        BIGNUM *data = BN_new(), *a = BN_new(), *b = BN_new();
        BN_bin2bn(input, strlen(input), data);

        al_gamal_encrypt_data(&a, &b, data, g, k, p, y);

        char *a_hex = BN_bn2hex(a);
        char *b_hex = BN_bn2hex(b);

        size_t result_size = strlen(a_hex) + 2 + strlen(b_hex) + 1;
        char result[result_size];
        snprintf(result, result_size, "%s\r\n%s", a_hex, b_hex);

        write_chars_to_file(result, result_size, ENCRYPTED_FILE_NAME);
        OPENSSL_free(a_hex);
        OPENSSL_free(b_hex);
        BN_free(a);
        BN_free(b);
        BN_free(data);

        stage = TERMINATE;
        printf("Exchange by sender side finished.\r\n");
    }
}
