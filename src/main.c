#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#define PATH_BUF_SIZE 4096

void init_repo() {
    mk_dir(".git");
    mk_dir(".git/objects");
    mk_dir(".git/refs");
    mk_dir(".git/refs/heads");

    const char* head = "ref: refs/heads/main";
    write_file(".git/HEAD", (const unsigned char*)head, strlen(head), 0664);

    printf("initialized empty repository\n");
}

int main() {

    return 0;
}
