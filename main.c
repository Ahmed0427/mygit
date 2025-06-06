#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <zlib.h>

bool is_dir_exist(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

void mkdir_handle_err(const char *dir) {
    int ret = mkdir(dir, 0775);
    if (ret != 0) {
        perror("mkdir error");
        exit(1);
    }
}

void init_repo() {
    mkdir_handle_err(".git");
    mkdir_handle_err(".git/objects");
    mkdir_handle_err(".git/refs");
    mkdir_handle_err(".git/refs/heads");

    int fd = open(".git/HEAD", O_CREAT | O_RDWR, 0664);
    if (fd == -1) {
        perror("open error");
        exit(1);
    }
    char *head_content = "ref: refs/heads/main";
    write(fd, head_content, strlen(head_content));
    close(fd);

    printf("initialized empty repository\n");
}

char *hash_object(char* data, size_t data_size, char* type, bool write_flag) {
    char header[64] = {0};
    sprintf(header, "%s %zu", type, data_size);
    size_t all_data_size = strlen(header) + data_size + 1;
    unsigned char* all_data = calloc(all_data_size, sizeof(char));
    memcpy(all_data, header, strlen(header));
    memcpy(all_data + strlen(header) + 1, data, data_size);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(all_data, all_data_size, hash);

    char *sha1 = calloc(2 * SHA_DIGEST_LENGTH + 1, sizeof(char));
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(sha1 + i * 2, "%02x", hash[i]);
    }
    if (write_flag) {
        char dir_path[16];
        char obj_path[16 + 38];
        sprintf(dir_path, "%s/%s/%c%c", ".git", "objects", sha1[0], sha1[1]);
        sprintf(obj_path, "%s/%s", dir_path, sha1 + 2);
        printf("%s\n", sha1);
        printf("%s\n", obj_path);
        if (!is_dir_exist(dir_path)) {
            mkdir_handle_err(dir_path);
        }
        size_t compressed_len = all_data_size * 2;
        unsigned char* compressed = calloc(compressed_len, sizeof(char));
        compress(compressed, &compressed_len, all_data, all_data_size);
        compressed = realloc(compressed, compressed_len);
        int fd = open(obj_path, O_CREAT | O_RDWR, 0444);
        if (fd == -1) {
            perror("open error");
            exit(1);
        }
        write(fd, compressed, compressed_len);
        free(compressed);
    }
    free(all_data);
    all_data = NULL;
    return sha1;
}

int main() {
    init_repo();
    char* sha1 = hash_object("Hello World\n", 13, "blob", true);
    free(sha1);
    return 0;
}
