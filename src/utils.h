#ifndef UTILS_T
#define UTILS_T

#include <stdint.h>
#include <openssl/sha.h>

#define PATH_BUF_SIZE 4096

void err(const char* msg);

bool dir_exists(const char* path);

bool file_exists(const char* path);

void mk_dir(const char* dir);

void print_sha1(const uint8_t sha1[SHA_DIGEST_LENGTH]);

void sha1_to_hex(char *res, const uint8_t sha1[SHA_DIGEST_LENGTH]);

void free_str_arr(char** arr, int cnt);

int read_file(const char* path, unsigned char** data, int* size);

int write_file(const char* path, const unsigned char* data, size_t size, int mode);

void collect_files(const char* base, char*** files, int* cnt);

char** split_str(char* str, const char* del, size_t* toks_cnt);

char* join_str(char** toks, size_t count, const char* del);

#endif
