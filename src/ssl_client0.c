//#include <stdio.h>
//#include <sys/time.h>
//#include <string.h>
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


int main(void)
{
	BIO *sbio, *out;
	BIO *bio_err = 0;

	int len, res;
	char tmpbuf[2014];

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	if (!bio_err) {
		SSL_library_init();
		SSL_load_error_strings();
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	sbio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(sbio, &ssl);
	assert(ssl);

	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(sbio, "127.0.0.1:4433");

	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	res = BIO_do_connect(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error connecting to server\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	res = BIO_do_handshake(sbio);
	if (res <= 0) {
		fprintf(stderr, "Error establishing SSL connection\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	BIO_puts(sbio, "GET / HTTP/1.0\n\n");
	for (;;) {
		len = BIO_read(sbio, tmpbuf, 1024);
		if (len <= 0) break;
		BIO_write(out, tmpbuf, len);
	}

	BIO_free_all(sbio);
	BIO_free(out);
	
	return 0;
}