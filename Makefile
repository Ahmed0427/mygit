CC=gcc
CFLAGS=-Wall -Wextra -pedantic -ggdb
EXEC=mygit

$(EXEC): main.c
	$(CC) $(CFLAGS) -o $(EXEC) main.c
