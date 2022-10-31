#include <stdio.h>
//#include <stdlib.h>
//#include <sys/time.h>
//#include <time.h>
#include <string.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#define MAXSIGNSZ 1024
#define BUFFSZ 1024

void printStr(unsigned char astr[], int len);
void printResult(int result);

void makeSignature(unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv);
int signatureVerify(unsigned char plaintext[], int plsize, unsigned char sign[], int signSize, RSA *rsaPub);


/*
void getTimeSubstr(char buff[])
{
  struct timeval atime;
  struct timezone tzone;
  gettimeofday(&atime, &tzone);
  memcpy(buff, &(atime.tv_sec), 4);
  memcpy(buff+4, &(atime.tv_usec), 4);
}
*/


//int main(int argc, char *argv[])
int main()
{
	RSA *rsaPub = NULL, *rsaPriv = NULL;
	unsigned char pt[BUFFSZ] = "This is a plaintext for RSA sign test.";
	unsigned char rands[BUFFSZ] = { 0, };
	unsigned char sign[MAXSIGNSZ] = { 0, };
	int plsize, result;
	unsigned int ssize;

	plsize = strlen((char*)pt);
	printf("Org text: %s - ", pt);
	printStr(pt, plsize);
	printf("\n");

	RAND_seed(rands, 0);
	rsaPriv = RSA_generate_key(512, RSA_F4, NULL, NULL);
	assert(rsaPriv);
	rsaPub = RSAPublicKey_dup(rsaPriv);
	assert(rsaPub);

	makeSignature(pt, plsize, sign, &ssize, rsaPriv);
	RSA_free(rsaPriv);

	printf("signature: ");
	printStr(sign, ssize);
	printf("\n");

	result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
	printResult(result);

	printf("\n 6th Char changed. ");
	pt[5] = '5';
	printf("Modified text: %s - ", pt);
	printStr(pt, plsize);
	printf("\n");

	result = signatureVerify(pt, plsize, sign, ssize, rsaPub);
	printResult(result);

	RSA_free(rsaPub);

	return(1);
}

void printStr(unsigned char astr[], int len)
{
	register int i;

	for (i = 0; i < len; i++)
		printf("%02x ", astr[i]);
	printf("\n");
}

void printResult(int result)
{
	switch (result) {
	case 1:
		printf("Signature is verified to be clear.\n");
		break;
	case 0:
		printf("Warning: Signature verification fails.\n");
		break;
	case -1:
		fprintf(stderr, "EVP_VerifyFinal error.\n");
		break;
	default:
		fprintf(stderr, "Invaild result from EVP_VerifyFinal()\n");
		break;
	}
}

void makeSignature(unsigned char *plaintext, int plsize, unsigned char *sign, unsigned int *signSize, RSA *rsaPriv)
{
	EVP_MD_CTX ctx;
	EVP_PKEY *pkey;
	int result;

	pkey = EVP_PKEY_new();
	result = EVP_PKEY_set1_RSA(pkey, rsaPriv);
	assert(result);

	EVP_MD_CTX_init(&ctx);
	result = EVP_SignInit_ex(&ctx, EVP_sha1(), NULL);
	assert(result);

	result = EVP_SignUpdate(&ctx, plaintext, plsize);
	assert(result);

	result = EVP_SignFinal(&ctx, sign, signSize, pkey);
	assert(result);
	assert(*signSize <= MAXSIGNSZ);

	EVP_MD_CTX_cleanup(&ctx);
	EVP_PKEY_free(pkey);
}

int signatureVerify(unsigned char plaintext[], int plsize, unsigned char sign[], int signSize, RSA *rsaPub)
{
	EVP_MD_CTX ctx;
	EVP_PKEY *pukey;
	int result;

	pukey = EVP_PKEY_new();
	result = EVP_PKEY_set1_RSA(pukey, rsaPub);
	assert(result);

	EVP_MD_CTX_init(&ctx);
	result = EVP_VerifyInit_ex(&ctx, EVP_sha1(), NULL);
	assert(result);

	result = EVP_VerifyUpdate(&ctx, plaintext, plsize);
	assert(result);

	result = EVP_VerifyFinal(&ctx, sign, signSize, pukey);

	EVP_MD_CTX_cleanup(&ctx);
	EVP_PKEY_free(pukey);

	return(result);
}