#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <openssl/des.h>

#define BUFFSZ 1024
#define SOCKSZ sizeof(struct sockaddr_in)
#define ACKSZ 5
#define TIMESKEW 2


int main(void)
{
	int res;
	int sockfd, sockfd_li;
	unsigned char buff[BUFFSZ];
	struct sockaddr_in server;
	struct timeval timeStamp, myTime;
	int fd;
	const_DES_cblock rawkey;
	DES_key_schedule keySched;
	DES_cblock iv;
	int cipherBSz;

	memset(&server, 0, sizeof(struct sockaddr_in));
	server.sin_port = 9999;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	sockfd_li = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd_li == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	res = bind(sockfd_li, (struct sockaddr *)&server, SOCKSZ);
	if (res == -1) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	res = listen(sockfd_li, 5);
	assert(res == 0);

	while (1) {
		sockfd = accept(sockfd_li, NULL, NULL);
		assert(sockfd >= 0);
		res = recv(sockfd, &cipherBSz, sizeof(int), 0);
		res = recv(sockfd, &buff, BUFFSZ, 0);
		assert(res == cipherBSz);

		gettimeofday(&myTime, NULL);

		fd = open("symmKey.sec", O_RDONLY);
		assert(fd != -1);
		res = read(fd, rawkey, 8);
		assert(res == 8);
		close(fd);

		DES_set_key(&rawkey, &keySched);

		bzero(iv, sizeof(DES_cblock));
		DES_ncbc_encrypt(buff, (unsigned char *)&timeStamp, cipherBSz, &keySched, (DES_cblock *)iv, DES_DECRYPT);

		if (abs(myTime.tv_sec - timeStamp.tv_sec) < TIMESKEW) {
			strcpy(buff, "yes");
			send(sockfd, &buff, 5, 0);
		}
		else {
			strcpy(buff, "no");
			send(sockfd, &buff, 5, 0);
		}
	}
}