#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/des.h>

#define MAXBUFF 1024

void getTimeSubstr(char buff[])
{
  struct timeval atime;
  struct timezone tzone;
  gettimeofday(&atime, &tzone);
  memcpy(buff, &(atime.tv_sec), 4);
  memcpy(buff+4, &(atime.tv_usec), 4);
}

RSA *readRSAKeyFile(char *pubKeyFn)
{
  FILE *fp;
  RSA *rsaPub;
  
  fp = fopen(pubKeyFn, "rb");
  assert(fp);
  rsaPub = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
  assert(rsaPub);
  fclose(fp);
  
  return(rsaPub);
}


void makeEnvelope(RSA *rsaPub, char *pfn, char *cfn)
{
  FILE *ifp, *ofp;
  unsigned char ptext[MAXBUFF];
  unsigned char ctext[MAXBUFF];
  int psize = 16, csize;
  unsigned char seedbuff[MAXBUFF];
  char mykey[EVP_MAX_KEY_LENGTH] = "\0";
  char iv[EVP_MAX_IV_LENGTH] = "\0";
  EVP_CIPHER_CTX ctx;
  int res;
  
  getTimeSubstr(seedbuff);
  RAND_seed(seedbuff, 8);
  RAND_bytes(mykey, EVP_MAX_KEY_LENGTH);
  RAND_bytes(iv, EVP_MAX_IV_LENGTH);
  
  csize = RSA_public_encrypt(psize, mykey, ctext, rsaPub, RSA_PKCS1_OAEP_PADDING);
  
  ofp = fopen(cfn, "wb");
  assert(ofp);
  fwrite(&csize, 1, sizeof(int), ofp);
  fwrite(ctext, 1, csize, ofp);
  
  EVP_CIPHER_CTX_init(&ctx);
  
  ifp = fopen(pfn, "rb");
  assert(ifp);
  
  EVP_CIPHER_CTX_init(&ctx);
  EVP_CipherInit_ex(&ctx, EVP_des_ede_cbc(), NULL, mykey, iv, DES_ENCRYPT);
  
  psize = fread(ptext, 1, MAXBUFF-8, ifp);
  while(psize > 0) {
    res = EVP_CipherUpdate(&ctx, ctext, &csize, ptext, psize);
    assert(res);
    fwrite(ctext, 1, csize, ofp);
    psize = fread(ptext, 1, MAXBUFF-8, ifp);
  }
  
  res = EVP_CipherFinal_ex(&ctx, ctext, &csize);
  assert(res);
  fwrite(ctext, 1, csize, ofp);
  
  fclose(ifp);
  fclose(ofp);
}



int main(int argc, char *argv[])
{
  RSA *rsaPub;
  
  assert(argc == 4);
  
  rsaPub = readRSAKeyFile(argv[1]);
  
  makeEnvelope(rsaPub, argv[2], argv[3]);
  RSA_free(rsaPub);
  
  return(0);
}
