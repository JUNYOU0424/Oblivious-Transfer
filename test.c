#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "./crypto/aes.h"
#include "./crypto/rsa.h"
#include <time.h>
#define KEY_LENGTH 2048
#define PUB_EXP 3

unsigned long long int begin, end;
struct timespec START, END;
double time_used,server_time_used,client_time_used;
struct timespec temp;

struct timespec diff(struct timespec start, struct timespec end)
{
    struct timespec temp;
    if ((end.tv_nsec - start.tv_nsec) < 0)
    {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    }
    else
    {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}

static __inline__ unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc"
                         : "=a"(lo), "=d"(hi));
    return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

char *X0, *X1 = NULL;
void Gen_Random_Message(int len)
{
    char *raw_buf = NULL;
    char *after_padding_buf = NULL;
    int padding_size = 0;
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    srand(time(0));
    raw_buf = (char *)malloc(len);
    X0 = (char *)malloc(padding_size);
    X1 = (char *)malloc(len * 2);
    memcpy(raw_buf, "s" + rand() % 256, len);
    after_padding_buf = padding_buf(raw_buf, len, &padding_size);
    encrpyt_buf(after_padding_buf, &X0, padding_size);
    for (int i = 0; i < len * 2; i++)
    {
        X1[i] = X0[i] ^ rand() % 256;
    }
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
}

char *k = NULL;
void Gen_Rand(int len)
{
    char *raw_buf = NULL;
    char *after_padding_buf = NULL;
    int padding_size = 0;
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    srand(time(0));
    raw_buf = (char *)malloc(len);
    k = (char *)malloc(padding_size);
    memcpy(raw_buf, "k" + rand() % 256, len);
    after_padding_buf = padding_buf(raw_buf, len, &padding_size);
    encrpyt_buf(after_padding_buf, &k, padding_size);
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
}

int main()
{
    char *encrypt = NULL;
    char *message1 = malloc(16);
    char *message2 = malloc(16);
    char *decrypt_k0, *decrypt_k1 = NULL;
    char *m0, *m1 = NULL;
    int *encrypt_len = NULL;
    char *err;
    RSA *keypair1, *keypair2;

    // Generate Sender Random Message X0 X1
    Gen_Random_Message(8);
    printf("Gen_Random_Message Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    server_time_used += time_used;
    printf("Gen_Random_Message Time : %f ms\n", time_used);

    // Generate Reciever Random String k
    Gen_Rand(16);
    printf("Gen_Rand Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    client_time_used += time_used;
    printf("Gen_Rand Time : %f ms\n", time_used);

    // Generate Message
    for (int i = 0; i < 16; i++)
    {
        message1[i] = k[i] ^ X0[i];
        message2[i] = k[i] ^ X1[i];
    }

    // Generate RSA Public/Private Key
    clock_gettime(CLOCK_MONOTONIC, &START);
    begin = rdtsc();
    keypair1 = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    keypair2 = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
    printf("RSA_generate_key Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    server_time_used += time_used;
    printf("RSA_generate_key Time : %f ms\n", time_used);

    // Encrypt k using choosen key
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    encrypt = malloc(RSA_size(keypair1));
    err = malloc(130);
    Encrypt(encrypt, keypair1, err, k);
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
    printf("Encrypt Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    client_time_used += time_used;
    printf("Encrypt Time : %f ms\n", time_used);

    // Decrypt using two different private key
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    decrypt_k0 = malloc(256);
    Decrypt(decrypt_k0, encrypt, err, keypair1);

    decrypt_k1 = malloc(256);
    Decrypt(decrypt_k1, encrypt, err, keypair2);
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
    printf("Decrypt Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    server_time_used += time_used;
    printf("Decrypt Time : %f ms\n", time_used);

#ifdef Debug
    printf("Generate X0,X1 : \n");
    printf_buff(X0, 16);
    printf_buff(X1, 16);
    printf("Generate k : \n");
    printf_buff(k, 16);
    printf("Clear Text :\n");
    printf_buff(message1, 16);
    printf_buff(message2, 16);
    printf("Encrypt :\n");
    printf_buff(encrypt, 128);
    printf("Decrypt k0:\n");
    printf_buff(decrypt_k0, 16);
    printf("Decrypt k1:\n");
    printf_buff(decrypt_k1, 16);
#endif
    //mask message
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    for (int i = 0; i < 16; i++)
    {
        message1[i] ^= decrypt_k0[i];
        message2[i] ^= decrypt_k1[i];
    }
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
    printf("Mask Message Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    server_time_used += time_used;
    printf("Mask Message Time : %f ms\n", time_used);

#ifdef Debug
    printf("Encrypt Text :\n");
    printf_buff(message1, 16);
    printf_buff(message2, 16);

#endif
    //unmask message
    begin = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &START);
    for (int i = 0; i < 16; i++)
    {
        message1[i] ^= k[i];
        message2[i] ^= k[i];
    }
    end = rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &END);
    printf("Unmask Message Cycle : %llu cycle\n", (end - begin));
    temp = diff(START, END);
    time_used = temp.tv_sec + (double)temp.tv_nsec / 1000000.0;
    client_time_used += time_used;
    printf("Unmask Message Time : %f ms\n", time_used);
    printf("Server Total Computation Time : %f ms\n", server_time_used);
    printf("Client Total Computation Time : %f ms\n", client_time_used);
#ifdef Debug
    printf("Decrypt Text :\n");
    printf_buff(message1, 16);
    printf_buff(message2, 16);
#endif
}