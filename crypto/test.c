#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "rsa.h"
#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS
#define WRITE_TO_FILE

int main(){
    /*size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   msg[KEY_LENGTH/8] = {'a','b','c','d'};;  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL; 
    int    *encrypt_len = NULL;   // Decrypted message
    char   *err;               // Buffer for any error messages
    char   *pri_key=NULL;           // Private key
    char   *pub_key=NULL;           // Public key
    // Generate key pair
    //printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    //printf("\n%s\n%s\n", pri_key, pub_key);*/
    char   msg[KEY_LENGTH/8] = {'a','b','c','d'};;  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL; 
    int    *encrypt_len = NULL;   // Decrypted message
    char   *err;       
    RSA *keypair1,*keypair2;
    keypair1 = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    keypair2 = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    encrypt = malloc(RSA_size(keypair1));
    err = malloc(130);
    Encrypt(encrypt,keypair1,err,msg);
    printf("Encrypt :%s\n",encrypt);
    decrypt = malloc(256);
    Decrypt(decrypt,encrypt,err,keypair1);
    printf("Decrypt :%s\n",decrypt);

    /*encrypt = malloc(RSA_size(keypair1));
    err = malloc(130);
    Encrypt(encrypt,keypair2,err,msg);
    printf("Encrypt :%s\n",encrypt);
    decrypt = malloc(256);
    Decrypt(decrypt,encrypt,err,keypair2);
    printf("Decrypt :%s\n",decrypt);*/
}