//#include "stdafx.h"
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

int main(int argc, char *argv[])
{
  
  BIO *keyBIO = NULL;
  BIO *errBIO = NULL;
  RSA *rsa=NULL;

  char keyFile[100];
  char KeyFormat[10];
  char encType[10];
  char keyType[10];

  char inFile[100];
  char outFile[100];

  BIO *inBIO = NULL;
  BIO *outBIO = NULL;

  
  if ((errBIO=BIO_new(BIO_s_file())) != NULL)
      BIO_set_fp(errBIO,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
  
  
  
  printf("Select Enc or Dec (e,d) : ");
  scanf("%s",encType);
    
  printf("Select Private Key or Public Key (pri,pub) : ");
  scanf("%s",keyType);
  
  
  printf("Input Key File Name : ");
  scanf("%s",keyFile);
 
  
  printf("Input the Format of Key File (PEM,DER) : ");
  scanf("%s",KeyFormat);

  
  printf("Input the Input File Name : ");
  scanf("%s",inFile);

  
  printf("Input the Output File Name : ");
  scanf("%s",outFile);

  
  keyBIO = BIO_new(BIO_s_file());
  if (keyBIO == NULL)
  {
    ERR_print_errors(errBIO);
    exit(1);
   }

  
  if (BIO_read_filename(keyBIO,keyFile) <= 0)
  {
    BIO_printf(errBIO,"Key File [%s] Open Error.",keyFile);
    ERR_print_errors(errBIO);
    exit(1);
  }
   
  
  if (strcmp(KeyFormat,"DER")==0)
  {
  
    if  (strcmp(keyType,"pub")==0)
      rsa = d2i_RSAPublicKey_bio(keyBIO,NULL);
    else
      rsa = d2i_RSAPrivateKey_bio(keyBIO,NULL);

  }
  
  else if(strcmp(KeyFormat,"PEM")==0)
  {
    
    if  (strcmp(keyType,"pub")==0) 
      rsa = PEM_read_bio_RSA_PUBKEY(keyBIO,NULL,NULL,NULL);
    else
      rsa = PEM_read_bio_RSAPrivateKey(keyBIO,NULL,NULL,NULL);
  }else
  {
    BIO_printf(errBIO,"unknown format [%s] error.",KeyFormat);
  }

  
  if (rsa == NULL)
  {
    BIO_printf(errBIO,"Key Load Error.");
    ERR_print_errors(errBIO);
    exit(1);
  }
    
  
  inBIO = BIO_new_file(inFile,"rb");
  if (!inBIO)
  {
    BIO_printf(errBIO,"input File [%s] Open Error.",inFile);
    ERR_print_errors(errBIO);
    exit(1);
  }
  
  outBIO = BIO_new_file(outFile,"wb");
  if (!outBIO)
  {
    BIO_printf(errBIO,"Output File [%s] Open Error.",outFile);
    ERR_print_errors(errBIO);
    exit(1);
  }


  int keySize = RSA_size(rsa);

  unsigned char * inBuffer = (unsigned char *)malloc(keySize*2);
  unsigned char * outBuffer = (unsigned char *)malloc(keySize);


  unsigned char pad = RSA_PKCS1_PADDING;


  int inLength = BIO_read(inBIO,inBuffer,keySize*2);

  int outLength = 0;

  if ( (strcmp(encType,"e")==0) && (strcmp(keyType,"pub")==0) )
     outLength = RSA_public_encrypt(inLength,inBuffer,outBuffer,rsa,pad);

  else if ( (strcmp(encType,"e")==0) && (strcmp(keyType,"pri")==0) )
     outLength = RSA_private_encrypt(inLength,inBuffer,outBuffer,rsa,pad);

  else if ( (strcmp(encType,"d")==0) && (strcmp(keyType,"pub")==0) )
     outLength = RSA_public_decrypt(inLength,inBuffer,outBuffer,rsa,pad);

  else if ( (strcmp(encType,"d")==0) && (strcmp(keyType,"pri")==0) )
     outLength = RSA_private_decrypt(inLength,inBuffer,outBuffer,rsa,pad);


  if (outLength <= 0)
  {
    BIO_printf(errBIO,"RSA Enc Error");
    ERR_print_errors(errBIO);
    exit(1);
  } 

  
  BIO_write(outBIO, outBuffer, outLength);

  BIO_printf(errBIO,"Completed!");
  
  
  if (keyBIO != NULL)
    BIO_free(keyBIO);
  if (rsa != NULL)
    RSA_free(rsa);
    free(inBuffer);
  free(outBuffer);

  return 0;
}