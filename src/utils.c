#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

void err(const char* msg) {
    perror(msg);
    exit(1);
}

bool dir_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

bool file_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

void mk_dir(const char* dir) {
    if (mkdir(dir, 0775) != 0) {
        err("mkdir error");
    }
}

void print_sha1(const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    assert(sha1 != NULL);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", sha1[i]);
    }
}

char* sha1_to_hex(const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    assert(sha1 != NULL);
    char* res = malloc(SHA_DIGEST_LENGTH * 2 + 1);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(res + i * 2, "%02x", sha1[i]);
    }
    res[SHA_DIGEST_LENGTH * 2] = '\0'; 
    return res;
}

void free_str_arr(char** arr, int cnt) {
    for (int i = 0; i < cnt; i++) {
        free(arr[i]);
    }
    free(arr);
}

int read_file(const char* path, unsigned char** data, int* size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "'%s' failed to read: %s\n", path, strerror(errno));
        return -1;
    }

    int fsize = lseek(fd, 0, SEEK_END);
    if (fsize == -1) {
        perror("lseek error");
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);

    unsigned char* buf = malloc(fsize);
    if (!buf) {
        close(fd);
        return -1;
    }

    int rb = read(fd, buf, fsize);
    if (rb != fsize) {
        perror("read error");
        free(buf);
        close(fd);
        return -1;
    }

    *size = fsize;
    *data = buf;
    close(fd);
    return 0;
}

int write_file(const char* path, const unsigned char* data,
               size_t size, int mode) {

    int fd = open(path, O_CREAT | O_RDWR, mode);
    if (fd == -1) {
        fprintf(stderr, "'%s' failed to write: %s\n", path, strerror(errno));
        return -1;
    }

    ssize_t wb = write(fd, data, size);
    close(fd);

    return (wb == (ssize_t)size) ? 0 : -1;
}

void collect_files(const char* base, char*** files, int* cnt) {
    const int cap = 16;
    int stk_cap = cap;
    char** stk = calloc(stk_cap, sizeof(char*));
    stk[0] = strdup(base);
    int stk_sz = 1;

    int lst_cap = cap;
    *files = calloc(lst_cap, sizeof(char*));
    *cnt = 0;

    while (stk_sz > 0) {
        stk_sz--;
        char* cdir = stk[stk_sz];
        DIR* dir = opendir(cdir);

        if (!dir) {
            free(cdir);
            continue;
        }

        struct dirent* ent;
        char path[PATH_BUF_SIZE] = {0};

        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) {
                continue;
            }

            if (strcmp(cdir, ".") != 0) {
                snprintf(path, sizeof(path), "%s/%s", cdir, ent->d_name);
            } else {
                snprintf(path, sizeof(path), "%s", ent->d_name);
            }

            struct stat st;
            if (stat(path, &st) == -1) {
                continue;
            }

            if (S_ISDIR(st.st_mode)) {
                if (strcmp(ent->d_name, ".git") != 0) {
                    if (stk_sz >= stk_cap) {
                        stk_cap *= 2;
                        stk = realloc(stk, stk_cap * sizeof(char*));
                    }
                    stk[stk_sz] = strdup(path);
                    stk_sz++;
                }
            } else {
                if (*cnt >= lst_cap) {
                    lst_cap *= 2;
                    *files = realloc(*files, lst_cap * sizeof(char*));
                }
                (*files)[*cnt] = strdup(path);
                (*cnt)++;
            }
        }

        free(cdir);
        closedir(dir);
    }

    free(stk);
}

char** split_str(char* org_str, const char* del, size_t* toks_cnt) {
    char* str = strdup(org_str);

    size_t cap = 1, sz = 0;
    char** toks = malloc(sizeof(char*) * cap);
    if (!toks) {
        *toks_cnt = 0;
        return NULL;
    }

    char* tok = strtok(str, del);
    while (tok != NULL) {
        if (sz >= cap) {
            cap *= 2;
            char** tmp = realloc(toks, sizeof(char*) * cap);
            if (!tmp) {
                free_str_arr(toks, sz);
                *toks_cnt = 0;
                return NULL;
            }
            toks = tmp;
        }

        toks[sz] = strdup(tok);
        if (!toks[sz]) {
            free_str_arr(toks, sz);
            *toks_cnt = 0;
            return NULL;
        }

        sz++;
        tok = strtok(NULL, del);
    }

    char** tmp = realloc(toks, sizeof(char*) * (sz + 1));
    if (!tmp) {
        free(toks);
        *toks_cnt = 0;
        return NULL;
    }
    toks = tmp;
    toks[sz] = NULL;

    *toks_cnt = sz;
    free(str);
    return toks;
}

char* join_str(char** toks, size_t count, const char* del) {
    if (count == 0) return strdup("");

    size_t del_len = strlen(del);
    size_t total_len = 0;

    for (size_t i = 0; i < count; ++i) {
        if (toks[i] != NULL) total_len += strlen(toks[i]);
        if (i < count - 1) total_len += del_len;
    }

    char* result = malloc(total_len + 1);
    if (!result) return NULL;

    result[0] = '\0';
    for (size_t i = 0; i < count; ++i) {
        strcat(result, toks[i]);
        if (i < count - 1) strcat(result, del);
    }

    return result;
}
