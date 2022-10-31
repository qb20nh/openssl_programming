#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#define MAXBUFF 128

void getTimeSubstr(char buff[])
{
    struct timeval atime;
    struct timezone timeZone;
    gettimeofday(&atime, &timeZone);
    memcpy(buff, &(atime.tv_sec), 4);
    memcpy(buff + 4, &(atime.tv_usec), 4);
}

int main(void)
{
    // RSA *rsaPrivate = NULL, *rsaPublic = NULL;
    // char seedBuffer[MAXBUFF];
    // FILE *publicFile, *privateFile;
    // getTimeSubstr(seedBuffer);
    // RAND_seed(seedBuffer, 8);
    // rsaPrivate = RSA_generate_key(512, RSA_F4, NULL, NULL);
    // if (rsaPrivate == NULL)
    // {
    //     fprintf(stderr, "RSA generate key error.\n");
    //     return (0);
    // }
    // rsaPublic = RSAPublicKey_dup(rsaPrivate);
    // if (rsaPublic == NULL)
    // {
    //     fprintf(stderr, "RSA public key copy error.\n");
    //     return (0);
    // }
    // publicFile = fopen("public_key.pem", "w");
    // assert(publicFile);
    // privateFile = fopen("private_key.pem", "w");
    // assert(privateFile);
    // if (!PEM_write_RSAPublicKey(publicFile, rsaPublic))
    //     fprintf(stderr, "Writing public key to file fails.\n");
    // if (!PEM_write_RSAPrivateKey(privateFile, rsaPrivate, NULL, NULL, 0, NULL, NULL))
    //     fprintf(stderr, "Writing private key to file fails.\n");
    // fclose(publicFile);
    // fclose(privateFile);
    // RSA_free(rsaPrivate);
    // RSA_free(rsaPublic);
    // exit(0);

    unsigned int primes = 3;
    unsigned int bits = 4096;
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    BIO *bio_out = BIO_new_file("key.pem", "wb");

    EVP_PKEY_keygen_init(pctx);

    params[0] = OSSL_PARAM_construct_uint("bits", &bits);
    params[1] = OSSL_PARAM_construct_uint("primes", &primes);
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, params);

    EVP_PKEY_generate(pctx, &pkey);
    EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
    EVP_PKEY_CTX_free(pctx);

    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    BIO_free_all(bio_out);

    exit(0);
}
