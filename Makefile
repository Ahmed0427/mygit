CC=gcc
CFLAGS=-Wall -Wextra -pedantic -ggdb
ZLIB_FLAG=-lz
SHA_FLAG=-lcrypto

EXEC=mygit

$(EXEC): main.c
	@$(CC) $(CFLAGS) -o $(EXEC) main.c $(ZLIB_FLAG) $(SHA_FLAG)
