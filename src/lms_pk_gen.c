//#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define TRUE 1
// CallBack Func
static void genrsa_cb(int p, int n, void *arg);


int main(int argc, char **argv)
{

 int keyLenInput = 512; 
 char outPublicKeyFile[50];  
 char outPrivateKeyFile[50]; 

 unsigned int isPem = TRUE; 

 BIO *publicOut=NULL;   
 BIO *privateOut=NULL;  
 BIO *bio_stdout=NULL;  

 RSA *rsa=NULL;   
 
 printf("Input Key Length : ");
 scanf("%d",&keyLenInput);

 printf("Public Key File Name : ");
 scanf("%s",outPublicKeyFile);

 printf("Private Key File Name : ");
 scanf("%s",outPrivateKeyFile);

 
 
 if ((bio_stdout=BIO_new(BIO_s_file())) != NULL)
 {
   BIO_set_fp(bio_stdout,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
 }    
 
 if ((publicOut=BIO_new(BIO_s_file())) == NULL)
 {
   printf("PubKey BIO Gen Error. %s",outPublicKeyFile);
      exit(1);
 } 
 
 if ((privateOut=BIO_new(BIO_s_file())) == NULL)
 {
   printf("PrivKey BIO Gen Error. %s",outPublicKeyFile);
      exit(1);
 } 
 
 if (BIO_write_filename(publicOut,outPublicKeyFile) <= 0)
 {
      printf("PubKey File BIO Gen Error. %s",outPublicKeyFile);
      exit(1);
 }
 
 if (BIO_write_filename(privateOut,outPrivateKeyFile) <= 0)
 {
      printf("PriKey File BIO Gen Error. %s",outPrivateKeyFile);
      exit(1);
 }

 RAND_screen();  // gen seed

 
 rsa=RSA_generate_key(keyLenInput,RSA_F4,genrsa_cb,NULL);

 if (isPem)
 {
 
  if (!PEM_write_bio_RSA_PUBKEY(bio_stdout,rsa))
  {
   printf("1 PubKey PEM File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
  printf("\n\n");
  
  if (!PEM_write_bio_RSAPrivateKey(bio_stdout,rsa,NULL,NULL,0,NULL,NULL))
  { 
   printf("1 PriKey PEM File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
  
  if (!PEM_write_bio_RSA_PUBKEY(publicOut,rsa))
  {
   printf("2 PubKey PEM File Gen Error %s",outPrivateKeyFile);
   exit(1);
  }
  
  if (!PEM_write_bio_RSAPrivateKey(privateOut,rsa,NULL,NULL,0,NULL,NULL))
  { 
   printf("2 PriKey PEM File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
 }else  
 {
  printf("DER PUBLIC KEY\n");

  
  if (!i2d_RSA_PUBKEY_bio(bio_stdout,rsa))
  {
   printf("1 PubKey DER File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
  
  printf("\n\n");
  printf("DER PRIVATE KEY\n");
  printf("\n");

  
  if (!i2d_RSAPrivateKey_bio(bio_stdout,rsa))
  { 
   printf("1 PriKey DER File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }

  
  if (!i2d_RSA_PUBKEY_bio(publicOut,rsa))
  {
   printf("2 PubKey DER File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
  
  
  if (!i2d_RSAPrivateKey_bio(privateOut,rsa))
  { 
   printf("2 PriKey DER File Gen Error. %s",outPrivateKeyFile);
   exit(1);
  }
 }

 
 if (rsa != NULL) RSA_free(rsa);
 
 if (publicOut != NULL) BIO_free_all(publicOut);
 if (privateOut != NULL) BIO_free_all(privateOut);
  
 return 0;
   
}


static void genrsa_cb(int p, int n, void *arg)
{
 char c='*';

 if (p == 0) c='.';
 if (p == 1) c='+';
 if (p == 2) c='*';
 if (p == 3) c='\n';
 printf("%c",c);
}