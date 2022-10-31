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

int _tmain(int argc, _TCHAR* argv[])
{
  // ���� ����
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

  // ǥ�� ȭ�� ��� BIO ����
  if ((errBIO=BIO_new(BIO_s_file())) != NULL)
      BIO_set_fp(errBIO,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
  
  
    // ��ȣȭ�� �Ұ��� ��ȣȭ�� �� ���� ����
  printf("��ȣȭ, ��ȣȭ ���� (e,d) : ");
  scanf("%s",encType);
    // Ű�� ����Ű�� ��� �� ����, ����Ű�� ��� �� ���� ����
  printf("����Ű, ����Ű ���� (pri,pub) : ");
  scanf("%s",keyType);
  
  // Ű ���ϸ� �Է�
  printf("Ű ������ �Է� �ϼ��� : ");
  scanf("%s",keyFile);
 
  // Ű ���� ���� �Է�
  printf("Ű ������ ������ �Է� �ϼ��� (PEM,DER) : ");
  scanf("%s",KeyFormat);

  // �Է� ���ϸ� �Է�
  printf("�Է� ���ϸ��� �Է� �ϼ��� : ");
  scanf("%s",inFile);

  // �ͷ� ���ϸ� �Է�
  printf("��� ���ϸ��� �Է� �ϼ��� : ");
  scanf("%s",outFile);

  // Ű ���� BIO����
  keyBIO = BIO_new(BIO_s_file());
  if (keyBIO == NULL)
  {
    ERR_print_errors(errBIO);
    exit(1);
   }

  // Ű ���� ����
  if (BIO_read_filename(keyBIO,keyFile) <= 0)
  {
    BIO_printf(errBIO,"Ű ���� [%s] �� ���µ� ������ �߻� �߽��ϴ�.",keyFile);
    ERR_print_errors(errBIO);
    exit(1);
  }
   
  // DER �����̸�, Ű ���� BIO���� Ű ������ �о rsa ����ü �������� ��ȯ
  if (strcmp(KeyFormat,"DER")==0)
  {
    // ����Ű�� ����Ű�� ���� �ٸ� �Լ� ���
    if  (strcmp(keyType,"pub")==0)
      rsa = d2i_RSAPublicKey_bio(keyBIO,NULL);
    else
      rsa = d2i_RSAPrivateKey_bio(keyBIO,NULL);

  }
  // PEM �����̸�, Ű ���� BIO���� Ű ������ �о rsa ����ü �������� ��ȯ
  else if(strcmp(KeyFormat,"PEM")==0)
  {
    // ����Ű�� ����Ű�� ���� �ٸ� �Լ� ���
    if  (strcmp(keyType,"pub")==0) 
      rsa = PEM_read_bio_RSA_PUBKEY(keyBIO,NULL,NULL,NULL);
    else
      rsa = PEM_read_bio_RSAPrivateKey(keyBIO,NULL,NULL,NULL);
  }else
  {
    BIO_printf(errBIO,"�� �� ���� ���� [%s] �Դϴ�.",KeyFormat);
  }

  // Ű�� �ε� �ϴµ� ���� �߻�
  if (rsa == NULL)
  {
    BIO_printf(errBIO,"Ű�� �ε� �� �� �����ϴ�.");
    ERR_print_errors(errBIO);
    exit(1);
  }
    
  // �Է� ���Ͽ��� BIO ����
  inBIO = BIO_new_file(inFile,"rb");
  if (!inBIO)
  {
    BIO_printf(errBIO,"�Է� ���� [%s] �� ���µ� ������ �߻� �߽��ϴ�.",inFile);
    ERR_print_errors(errBIO);
    exit(1);
  }
  // ��� ���Ͽ��� BIO ����
  outBIO = BIO_new_file(outFile,"wb");
  if (!outBIO)
  {
    BIO_printf(errBIO,"��� ���� [%s] �� ���� �ϴµ� ������ �߻� �߽��ϴ�.",outFile);
    ERR_print_errors(errBIO);
    exit(1);
  }

  // ���� Ű�� ���̸� ����
  int keySize = RSA_size(rsa);

  // �Է¹� ������ �� ���ۿ�, ��¹� ������ �� ���� ����
  // �Է� ������ ���̴� Ű ������ �ι�, ��� ���۴� Ű ���̿� ����
  unsigned char * inBuffer = (unsigned char *)malloc(keySize*2);
  unsigned char * outBuffer = (unsigned char *)malloc(keySize);

  // �е�  ����, �Ϲ����� �е����� ���
  unsigned char pad = RSA_PKCS1_PADDING;

  // �Է¹� ���Ͽ��� ���� �о� ���ۿ� ����
  int inLength = BIO_read(inBIO,inBuffer,keySize*2);

  int outLength = 0;
  // ����Ű�� ��ȣȭ �Ҷ�. �Է� ������ ������ ��ȣȭ �ؼ� ��� ���ۿ� ����
  if ( (strcmp(encType,"e")==0) && (strcmp(keyType,"pub")==0) )
     outLength = RSA_public_encrypt(inLength,inBuffer,outBuffer,rsa,pad);
  // ����Ű�� ��ȣȭ �Ҷ�. �Է� ������ ������ ��ȣȭ �ؼ� ��� ���ۿ� ����
  else if ( (strcmp(encType,"e")==0) && (strcmp(keyType,"pri")==0) )
     outLength = RSA_private_encrypt(inLength,inBuffer,outBuffer,rsa,pad);
  // ����Ű�� ��ȣȭ �Ҷ�. �Է� ������ ������ ��ȣȭ �ؼ� ��� ���ۿ� ����
  else if ( (strcmp(encType,"d")==0) && (strcmp(keyType,"pub")==0) )
     outLength = RSA_public_decrypt(inLength,inBuffer,outBuffer,rsa,pad);
  // ����Ű�� ��ȣȭ �Ҷ�. �Է� ������ ������ ��ȣȭ �ؼ� ��� ���ۿ� ����
  else if ( (strcmp(encType,"d")==0) && (strcmp(keyType,"pri")==0) )
     outLength = RSA_private_decrypt(inLength,inBuffer,outBuffer,rsa,pad);

  // ��ȣȭ Ȥ�� ��ȣȭ�� ���� �߻� üũ
  if (outLength <= 0)
  {
    BIO_printf(errBIO,"RSA ��ȣȭ�� ���� �߻�");
    ERR_print_errors(errBIO);
    exit(1);
  } 

  // ��� ���Ͽ� ��� ������ ���� ����
  BIO_write(outBIO, outBuffer, outLength);

  BIO_printf(errBIO,"�Ϸ� �Ǿ����ϴ�.");
  
  // ��ü ����
  if (keyBIO != NULL)
    BIO_free(keyBIO);
  if (rsa != NULL)
    RSA_free(rsa);
    free(inBuffer);
  free(outBuffer);

  return 0;
}
 