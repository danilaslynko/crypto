#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <conio.h>
#include "crypto.h"
#define COMMON_PARAMS_FILE_NAME "common_p.param"

#define SENDER_FIRST_STEP_RESULT_FILENAME "sender_first"
#define RECEIVER_FIRST_STEP_RESULT_FILENAME "receiver_first"
#define SENDER_SECOND_STEP_RESULT_FILENAME "sender_second"

#define SENDER_LOCK "sender_lock"
#define RECEIVER_LOCK "receiver_lock"

#define UNKNOWN_MODE 1
#define UNABLE_TO_BECOME_SENDER 2
#define UNABLE_TO_BECOME_RECEIVER 3

typedef enum {
    INITIALIZE_PARAMETERS,
    WAIT_FOR_DATA,
    START_ENCRYPT_BY_SENDER,
    INTERMEDIARY_ENCRYPT_BY_RECEIVER,
    INTERMEDIARY_ENCRYPT_BY_SENDER,
    FINISH_DECRYPT_BY_RECEIVER,
    TERMINATE
} STAGE;

typedef enum {
    SENDER, RECEIVER
} MODE;

STAGE stage;

BIGNUM *p;
BIGNUM *first;
BIGNUM *second;

void start_listen(MODE mode);

void listen_sender();

void listen_receiver();

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
    stage = INITIALIZE_PARAMETERS;

    if (access(COMMON_PARAMS_FILE_NAME, F_OK) == 0) {
        char *buffer;
        long file_size;
        read_chars_from_file(&buffer, &file_size, COMMON_PARAMS_FILE_NAME);
        p = BN_new();
        BN_hex2bn(&p, buffer);
        free(buffer);
    } else {
        p = generate_big_prime();
        char *hex = BN_bn2hex(p);
        write_chars_to_file(hex, strlen(hex), COMMON_PARAMS_FILE_NAME);
        OPENSSL_free(hex);
    }

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

    shamir_generate_secret_data(p, &first, &second);
    start_listen(mode);

    getch();
    fclose(lock);
    if (mode == SENDER) {
        remove(SENDER_FIRST_STEP_RESULT_FILENAME);
        remove(SENDER_SECOND_STEP_RESULT_FILENAME);
        remove(SENDER_LOCK);
    } else {
        remove(RECEIVER_FIRST_STEP_RESULT_FILENAME);
        remove(RECEIVER_LOCK);
    }

    if (access(COMMON_PARAMS_FILE_NAME, F_OK) == 0) {
        remove(COMMON_PARAMS_FILE_NAME);
    }

    BN_free(p);
    BN_free(first);
    BN_free(second);

    return 0;
}

void start_listen(MODE mode) {
    stage = WAIT_FOR_DATA;
    if (mode == SENDER) listen_sender();
    else listen_receiver();
}

void listen_receiver() {
    while(1) {
        if (stage == WAIT_FOR_DATA) {
            if (access(SENDER_FIRST_STEP_RESULT_FILENAME, F_OK) == 0) {
                stage = INTERMEDIARY_ENCRYPT_BY_RECEIVER;

                char *sender_first_step_result_file_content;
                long file_length;
                read_chars_from_file(&sender_first_step_result_file_content, &file_length, SENDER_FIRST_STEP_RESULT_FILENAME);

                BIGNUM *sender_first_step_result = BN_new();
                BN_hex2bn(&sender_first_step_result, sender_first_step_result_file_content);

                BIGNUM *result = shamir_exp(sender_first_step_result, first, p);
                char *hex = BN_bn2hex(result);
                write_chars_to_file(hex, strlen(hex), RECEIVER_FIRST_STEP_RESULT_FILENAME);
                OPENSSL_free(hex);
                BN_free(result);
                BN_free(sender_first_step_result);
                free(sender_first_step_result_file_content);

                stage = INTERMEDIARY_ENCRYPT_BY_SENDER;
            }
        } else if (stage == INTERMEDIARY_ENCRYPT_BY_SENDER) {
            if (access(SENDER_SECOND_STEP_RESULT_FILENAME, F_OK) == 0) {
                stage = FINISH_DECRYPT_BY_RECEIVER;

                char *pre_result_file_content;
                long file_length;
                read_chars_from_file(&pre_result_file_content, &file_length, SENDER_SECOND_STEP_RESULT_FILENAME);

                BIGNUM *pre_result = BN_new();
                BN_hex2bn(&pre_result, pre_result_file_content);

                BIGNUM *result = shamir_exp(pre_result, second, p);
                int result_bits = BN_num_bits(result);
                size_t message_str_length = result_bits / (8 * sizeof(char)) + (result_bits % (8 * sizeof(char)) ? 2 : 1);
                unsigned char *result_message = malloc(message_str_length);
                BN_bn2bin(result, result_message);
                result_message[message_str_length - 1] = 0;
                printf("Received message:\r\n%s\r\n", result_message);
                BN_free(result);
                BN_free(pre_result);
                free(result_message);
                free(pre_result_file_content);

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
    while (1) {
        if (stage == WAIT_FOR_DATA) {
            unsigned char input[1024];
            printf("Enter input and press ENTER to start exchange:\r\n");
            scanf("%s", input);

            stage = START_ENCRYPT_BY_SENDER;
            BIGNUM *data = BN_new();
            BN_bin2bn(input, strlen(input), data);
            BIGNUM *result = shamir_exp(data, first, p);
            char *hex = BN_bn2hex(result);
            write_chars_to_file(hex, strlen(hex), SENDER_FIRST_STEP_RESULT_FILENAME);
            OPENSSL_free(hex);
            BN_free(result);
            BN_free(data);

            stage = INTERMEDIARY_ENCRYPT_BY_RECEIVER;
        } else if (stage == INTERMEDIARY_ENCRYPT_BY_RECEIVER) {
            if (access(RECEIVER_FIRST_STEP_RESULT_FILENAME, F_OK) == 0) {
                stage = INTERMEDIARY_ENCRYPT_BY_SENDER;

                char *receiver_first_step_result_file_content;
                long file_length;
                read_chars_from_file(&receiver_first_step_result_file_content, &file_length, RECEIVER_FIRST_STEP_RESULT_FILENAME);

                BIGNUM *receiver_first_step_result = BN_new();
                BN_hex2bn(&receiver_first_step_result, receiver_first_step_result_file_content);

                BIGNUM *result = shamir_exp(receiver_first_step_result, second, p);
                char *hex = BN_bn2hex(result);
                write_chars_to_file(hex, strlen(hex), SENDER_SECOND_STEP_RESULT_FILENAME);
                OPENSSL_free(hex);
                BN_free(result);
                BN_free(receiver_first_step_result);
                free(receiver_first_step_result_file_content);

                stage = TERMINATE;
            }
        } else if (stage == TERMINATE) {
            printf("Exchange by sender side finished.\r\n");
            break;
        }

        sleep(1);
    }
}
