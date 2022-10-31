//#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// �ݺ� �Լ� ����
static void genrsa_cb(int p, int n, void *arg);

// ���� �Լ� ����
int main(int argc, char **argv)
{

 int keyLenInput = 512; // Ű ����
 char outPublicKeyFile[50];  // ����Ű�� ����
 char outPrivateKeyFile[50]; // ����Ű�� ����

 bool isPem = true; // PEM ��������..

 BIO *publicOut=NULL;   // ����Ű�� ����Ǵ� ���� BIO
 BIO *privateOut=NULL;  // ����Ű�� ����Ǵ� ���� BIO
 BIO *bio_stdout=NULL;  // ȭ�鿡 ����� stdout BIO

 RSA *rsa=NULL;   // RSA ����ü
 
 printf("Ű ���� �Է� : ");  // Ű ���� �Է�
 scanf("%d",&keyLenInput);

 printf("������ ����Ű ���� �̸� �Է� : ");  // ����Ű�� ���� �� ���ϸ� �Է�
 scanf("%s",outPublicKeyFile);

 printf("������ ����Ű ���� �̸� �Է� : ");  // ����Ű�� ���� �� ���ϸ� �Է�
 scanf("%s",outPrivateKeyFile);

 
 // ǥ�� ȭ�� ��� BIO ����
 if ((bio_stdout=BIO_new(BIO_s_file())) != NULL)
 {
   BIO_set_fp(bio_stdout,stdout,BIO_NOCLOSE|BIO_FP_TEXT);
 }    
 // ����Ű�� ������ ���� BIO ����
 if ((publicOut=BIO_new(BIO_s_file())) == NULL)
 {
   printf("BIO ���� ����. %s",outPublicKeyFile);
      exit(1);
 } 
 // ����Ű�� ������ ���� BIO ����
 if ((privateOut=BIO_new(BIO_s_file())) == NULL)
 {
   printf("BIO ���� ����. %s",outPublicKeyFile);
      exit(1);
 } 
 // ���� BIO�� �ش� ����Ű ������ ���� ����
 if (BIO_write_filename(publicOut,outPublicKeyFile) <= 0)
 {
      printf("BIO ���� ����. %s",outPublicKeyFile);
      exit(1);
 }
 // ���� BIO�� �ش� ����Ű ������ ���� ����
 if (BIO_write_filename(privateOut,outPrivateKeyFile) <= 0)
 {
      printf("BIO ���� ����. %s",outPrivateKeyFile);
      exit(1);
 }

 RAND_screen();  // seed ����, ����

 // Ű ����
 rsa=RSA_generate_key(keyLenInput,RSA_F4,genrsa_cb,NULL);

 if (isPem)
 {
  // PEM �������� ǥ�� ȭ�� ��� BIO�� ����Ű ���
  if (!PEM_write_bio_RSA_PUBKEY(bio_stdout,rsa))
  {
   printf("PEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
  printf("\n\n");
  // PEM �������� ǥ�� ȭ�� ��� BIO�� ����Ű ���
  if (!PEM_write_bio_RSAPrivateKey(bio_stdout,rsa,NULL,NULL,0,NULL,NULL))
  { 
   printf("PEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
  // PEM �������� ���� BIO�� ����Ű ���
  if (!PEM_write_bio_RSA_PUBKEY(publicOut,rsa))
  {
   printf("PEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
  // PEM �������� ���� BIO�� ����Ű ���
  if (!PEM_write_bio_RSAPrivateKey(privateOut,rsa,NULL,NULL,0,NULL,NULL))
  { 
   printf("PEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
 }else  // ���� DEM �������� Ű ���� ��� �Ѵٸ�
 {
  printf("DER PUBLIC KEY\n");

  // DEM �������� ǥ�� ȭ�� ��� BIO�� ����Ű ���
  if (!i2d_RSA_PUBKEY_bio(bio_stdout,rsa))
  {
   printf("DEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
  
  printf("\n\n");
  printf("DER PRIVATE KEY\n");
  printf("\n");

  // DEM �������� ǥ�� ȭ�� ��� BIO�� ����Ű ���
  if (!i2d_RSAPrivateKey_bio(bio_stdout,rsa))
  { 
   printf("DEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }

  // DEM �������� ���� BIO�� ����Ű ���
  if (!i2d_RSA_PUBKEY_bio(publicOut,rsa))
  {
   printf("DEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
  
  // DEM �������� ���� BIO�� ����Ű ���
  if (!i2d_RSAPrivateKey_bio(privateOut,rsa))
  { 
   printf("DEM ���� ���� ���� %s",outPrivateKeyFile);
   exit(1);
  }
 }

 // RSA ����ü �޸𸮿��� ����
 if (rsa != NULL) RSA_free(rsa);
 // BIO�� �޸𸮿��� ����
 if (publicOut != NULL) BIO_free_all(publicOut);
 if (privateOut != NULL) BIO_free_all(privateOut);
  
 return 0;
   
}

// �ݺ� �Լ� 
static void genrsa_cb(int p, int n, void *arg)
{
 char c='*';
 // prime number e�� ���� ������ ǥ��
 if (p == 0) c='.';
 if (p == 1) c='+';
 if (p == 2) c='*';
 if (p == 3) c='\n';
 printf("%c",c);
}
 