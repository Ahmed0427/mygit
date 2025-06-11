#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#define SIG_SIZE 4
#define VER_SIZE 4
#define CNT_SIZE 4
#define HDR_SIZE (SIG_SIZE + VER_SIZE + CNT_SIZE)

#define CTIME_S_SIZE 4
#define CTIME_N_SIZE 4
#define MTIME_S_SIZE 4
#define MTIME_N_SIZE 4
#define DEV_SIZE 4
#define INO_SIZE 4
#define MODE_SIZE 4
#define UID_SIZE 4
#define GID_SIZE 4
#define FSIZE_SIZE 4
#define SHA1_SIZE SHA_DIGEST_LENGTH
#define FLAGS_SIZE 2

#define PATH_BUF_SIZE 4096
#define HDR_BUF_SIZE 64

typedef struct {
    char sig[SIG_SIZE];
    uint32_t ver;
    uint32_t cnt;
} idx_hdr_t;

typedef struct {
    uint32_t ctime_s;
    uint32_t ctime_n;
    uint32_t mtime_s;
    uint32_t mtime_n;
    uint32_t dev;
    uint32_t ino;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t fsize;
    uint8_t sha1[SHA_DIGEST_LENGTH];
    uint16_t flags;
    char* path;
} idx_entry_t;

typedef struct {
    idx_entry_t** entries;
    size_t size;
} idx_entries_t;

void err(const char* msg) {
    perror(msg);
    exit(1);
}

bool dir_exists(const char* path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

void mk_dir(const char* dir) {
    if (mkdir(dir, 0775) != 0) {
        err("mkdir error");
    }
}

void print_sha1(const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        printf("%02x", sha1[i]);
    }
}

void free_str_arr(char** arr, int cnt) {
    for (int i = 0; i < cnt; i++) {
        free(arr[i]);
    }
    free(arr);
}

void free_entry(idx_entry_t* e) {
    if (e) {
        free(e->path);
        free(e);
    }
}

void free_entries(idx_entries_t* ents) {
    if (!ents) return;

    for (size_t i = 0; i < ents->size; i++) {
        free_entry(ents->entries[i]);
    }
    free(ents->entries);
    free(ents);
}

int read_file(const char* path, unsigned char** data, int* size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open error");
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

int write_file(const char* path, const unsigned char* data, size_t size,
               int mode) {
    int fd = open(path, O_CREAT | O_RDWR, mode);
    if (fd == -1) {
        err("open error");
    }

    ssize_t wb = write(fd, data, size);
    close(fd);

    return (wb == (ssize_t)size) ? 0 : -1;
}

void init_repo() {
    mk_dir(".git");
    mk_dir(".git/objects");
    mk_dir(".git/refs");
    mk_dir(".git/refs/heads");

    const char* head = "ref: refs/heads/main";
    write_file(".git/HEAD", (const unsigned char*)head, strlen(head), 0664);

    printf("initialized empty repository\n");
}

unsigned char* hash_obj(const unsigned char* data, size_t data_size,
                        const char* type, bool write_to_disk) {
    char header[HDR_BUF_SIZE] = {0};
    snprintf(header, sizeof(header), "%s %zu", type, data_size);

    size_t total_size = strlen(header) + data_size + 1;
    unsigned char* combined_data = calloc(total_size, sizeof(char));
    if (!combined_data) return NULL;

    memcpy(combined_data, header, strlen(header));
    memcpy(combined_data + strlen(header) + 1, data, data_size);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(combined_data, total_size, hash);

    unsigned char* result_hash = malloc(SHA_DIGEST_LENGTH);
    if (result_hash) {
        memcpy(result_hash, hash, SHA_DIGEST_LENGTH);
    }

    if (write_to_disk && result_hash) {
        char dir_path[32];
        char obj_path[64];

        snprintf(dir_path, sizeof(dir_path), ".git/objects/%02x",
                 result_hash[0]);
        snprintf(obj_path, sizeof(obj_path), "%s/%02x", dir_path,
                 result_hash[1]);

        char hex_suffix[40] = {0};
        for (int i = 2; i < SHA_DIGEST_LENGTH; i++) {
            snprintf(hex_suffix + (i - 2) * 2, 3, "%02x", result_hash[i]);
        }
        strncat(obj_path, hex_suffix, sizeof(obj_path) - strlen(obj_path) - 1);

        if (!dir_exists(dir_path)) {
            mk_dir(dir_path);
        }

        size_t compressed_len = total_size * 2;
        unsigned char* compressed = malloc(compressed_len);
        if (compressed) {
            if (compress(compressed, &compressed_len, combined_data,
                         total_size) == Z_OK) {
                write_file(obj_path, compressed, compressed_len, 0444);
            }
            free(compressed);
        }
    }

    free(combined_data);
    return result_hash;
}

bool valid_hdr(const unsigned char* data, idx_hdr_t* hdr) {
    memcpy(hdr->sig, data, SIG_SIZE);
    if (memcmp(hdr->sig, "DIRC", 4) != 0) {
        fprintf(stderr, "invalid index signature\n");
        return false;
    }

    hdr->ver = ntohl(*(uint32_t*)(data + SIG_SIZE));
    if (hdr->ver != 2) {
        fprintf(stderr, "invalid index version\n");
        return false;
    }

    hdr->cnt = ntohl(*(uint32_t*)(data + SIG_SIZE + VER_SIZE));
    return true;
}

bool valid_chksum(const unsigned char* data, int size) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, size - SHA_DIGEST_LENGTH, hash);
    return memcmp(hash, data + size - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) ==
           0;
}

idx_entry_t* parse_entry(const unsigned char* data, int off) {
    idx_entry_t* e = calloc(1, sizeof(idx_entry_t));
    if (!e) return NULL;

    const unsigned char* ed = data + off;

    e->ctime_s = ntohl(*(uint32_t*)(ed + 0));
    e->ctime_n = ntohl(*(uint32_t*)(ed + 4));
    e->mtime_s = ntohl(*(uint32_t*)(ed + 8));
    e->mtime_n = ntohl(*(uint32_t*)(ed + 12));
    e->dev = ntohl(*(uint32_t*)(ed + 16));
    e->ino = ntohl(*(uint32_t*)(ed + 20));
    e->mode = ntohl(*(uint32_t*)(ed + 24));
    e->uid = ntohl(*(uint32_t*)(ed + 28));
    e->gid = ntohl(*(uint32_t*)(ed + 32));
    e->fsize = ntohl(*(uint32_t*)(ed + 36));

    memcpy(e->sha1, ed + 40, SHA_DIGEST_LENGTH);
    e->flags = ntohs(*(uint16_t*)(ed + 60));
    e->path = strdup((char*)(ed + 62));

    return e;
}

idx_entries_t* read_idx() {
    int size;
    unsigned char* data;

    if (read_file(".git/index", &data, &size) != 0) {
        return NULL;
    }

    if (!valid_chksum(data, size)) {
        fprintf(stderr, "invalid index checksum\n");
        free(data);
        return NULL;
    }

    idx_hdr_t hdr;
    if (!valid_hdr(data, &hdr)) {
        free(data);
        return NULL;
    }

    idx_entries_t* ents = calloc(1, sizeof(idx_entries_t));
    if (!ents) {
        free(data);
        return NULL;
    }

    ents->entries = calloc(hdr.cnt, sizeof(idx_entry_t*));
    ents->size = hdr.cnt;

    int off = HDR_SIZE;
    for (uint32_t i = 0; i < hdr.cnt; i++) {
        ents->entries[i] = parse_entry(data, off);
        if (!ents->entries[i]) {
            free_entries(ents);
            free(data);
            return NULL;
        }

        // Calculate next entry offset (8-byte aligned)
        off += ((62 + strlen(ents->entries[i]->path) + 8) / 8) * 8;
    }

    free(data);
    return ents;
}

void list_files(bool details) {
    idx_entries_t* ents = read_idx();
    if (!ents) return;

    for (size_t i = 0; i < ents->size; i++) {
        idx_entry_t* e = ents->entries[i];
        if (details) {
            uint16_t stage = (e->flags >> 12) & 0x3;
            printf("%06o ", e->mode);
            print_sha1(e->sha1);
            printf(" %d\t%s\n", stage, e->path);
        } else {
            printf("%s\n", e->path);
        }
    }

    free_entries(ents);
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

void print_modified(char** paths, int pcnt, idx_entries_t* idx) {
    bool hdr = false;

    for (int i = 0; i < pcnt; i++) {
        for (size_t j = 0; j < idx->size; j++) {
            if (strcmp(paths[i], idx->entries[j]->path) != 0) {
                continue;
            }

            int size;
            unsigned char* data;
            if (read_file(paths[i], &data, &size) != 0) {
                continue;
            }

            unsigned char* hash = hash_obj(data, size, "blob", false);
            bool mod =
                memcmp(hash, idx->entries[j]->sha1, SHA_DIGEST_LENGTH) != 0;

            if (mod) {
                if (!hdr) {
                    printf("  modified files:\n");
                    hdr = true;
                }
                printf("    %s\n", paths[i]);
            }

            free(hash);
            free(data);
            break;
        }
    }
}

void print_new(char** paths, int pcnt, idx_entries_t* idx) {
    bool hdr = false;

    for (int i = 0; i < pcnt; i++) {
        bool found = false;

        for (size_t j = 0; j < idx->size; j++) {
            if (strcmp(paths[i], idx->entries[j]->path) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            if (!hdr) {
                printf("  new files:\n");
                hdr = true;
            }
            printf("    %s\n", paths[i]);
        }
    }
}

void print_deleted(char** paths, int pcnt, idx_entries_t* idx) {
    bool hdr = false;

    for (size_t i = 0; i < idx->size; i++) {
        bool found = false;

        for (int j = 0; j < pcnt; j++) {
            if (strcmp(idx->entries[i]->path, paths[j]) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            if (!hdr) {
                printf("  deleted files:\n");
                hdr = true;
            }
            printf("    %s\n", idx->entries[i]->path);
        }
    }
}

void show_status() {
    int fcnt = 0;
    char** paths = NULL;
    collect_files(".", &paths, &fcnt);

    idx_entries_t* idx = read_idx();
    if (!idx) {
        free_str_arr(paths, fcnt);
        return;
    }

    print_modified(paths, fcnt, idx);
    printf("\n");
    print_new(paths, fcnt, idx);
    printf("\n");
    print_delelted(paths, fcnt, idx);

    free_entries(idx);
    free_str_arr(paths, fcnt);
}

int main() {
    show_status();
    return 0;
}
