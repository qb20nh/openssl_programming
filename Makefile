SRC=./src
TARGET=./target
CC = gcc
NAME = rsa_keygen
CFLAGS = -I /Users/taejongyoo/vcpkg/packages/openssl_arm64-osx/include/ -L /Users/taejongyoo/vcpkg/packages/openssl_arm64-osx/lib/ -g -Wall -o $(TARGET)/$(NAME).out -lcrypto
RM = rm -rf

all: clean default

default: build

build:
	$(CC) $(CFLAGS) $(SRC)/$(NAME).c

clean:
	$(RM) $(TARGET)/*.out
