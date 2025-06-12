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

#define PATH_BUF_SIZE 4096
#define HDR_BUF_SIZE 64

#define HDR_SIZE 12

typedef struct {
    char sig[4];
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
    idx_hdr_t* hdr;
    idx_entry_t** entries;
    size_t ext_size;
    uint8_t* ext;
} idx_t;

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
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", sha1[i]);
    }
}

void sha1_to_hex(char *res, const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(res + i * 2, "%02x", sha1[i]);
    }
    res[SHA_DIGEST_LENGTH * 2] = '\0'; 
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

void free_idx(idx_t* idx) {
    if (!idx) return;
    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        free_entry(idx->entries[i]);
    }
    if (idx->hdr) free(idx->hdr);
    if (idx->ext) free(idx->ext);
    free(idx->entries);
    free(idx);
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

int write_file(const char* path, const unsigned char* data,
               size_t size, int mode) {

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
    memcpy(hdr->sig, data, 4);
    if (memcmp(hdr->sig, "DIRC", 4) != 0) {
        fprintf(stderr, "invalid index signature\n");
        return false;
    }

    hdr->ver = ntohl(*(uint32_t*)(data + 4));
    if (hdr->ver != 2) {
        fprintf(stderr, "invalid index version\n");
        return false;
    }

    hdr->cnt = ntohl(*(uint32_t*)(data + 8));
    return true;
}

bool valid_chksum(const unsigned char* data, int size) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, size - SHA_DIGEST_LENGTH, hash);
    return memcmp(hash, data + size - SHA_DIGEST_LENGTH,
                  SHA_DIGEST_LENGTH) == 0;
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

idx_t* read_idx() {
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

    idx_hdr_t *hdr = malloc(HDR_SIZE);
    if (!valid_hdr(data, hdr)) {
        free(data);
        return NULL;
    }

    idx_t* idx = calloc(1, sizeof(idx_t));
    if (!idx) {
        free(data);
        return NULL;
    }

    idx->hdr = hdr;
    idx->entries = calloc(hdr->cnt, sizeof(idx_entry_t*));

    int off = HDR_SIZE;
    for (uint32_t i = 0; i < hdr->cnt; i++) {
        idx->entries[i] = parse_entry(data, off);
        if (!idx->entries[i]) {
            free_idx(idx);
            free(data);
            return NULL;
        }
        // Calculate next entry offset (8-byte aligned)
        off += ((62 + strlen(idx->entries[i]->path) + 8) / 8) * 8;
    }

    int ext_size = size - off - 20;
    idx->ext = malloc(ext_size);
    idx->ext_size = ext_size;
    memcpy(idx->ext, data + off, ext_size);

    free(data);
    return idx;
}

int list_files(bool details) {
    idx_t* idx = read_idx();
    if (!idx) return -1;

    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        idx_entry_t* e = idx->entries[i];
        if (details) {
            uint16_t stage = (e->flags >> 12) & 0x3;
            printf("%06o ", e->mode);
            print_sha1(e->sha1);
            printf(" %d\t%s\n", stage, e->path);
        } else {
            printf("%s\n", e->path);
        }
    }

    free_idx(idx);
    return 0;
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

void print_modified(char** paths, int pcnt, idx_t* idx) {
    bool hdr = false;

    for (int i = 0; i < pcnt; i++) {
        for (size_t j = 0; j < idx->hdr->cnt; j++) {
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

void print_new(char** paths, int pcnt, idx_t* idx) {
    bool hdr = false;

    for (int i = 0; i < pcnt; i++) {
        bool found = false;

        for (size_t j = 0; j < idx->hdr->cnt; j++) {
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

void print_deleted(char** paths, int pcnt, idx_t* idx) {
    bool hdr = false;

    for (size_t i = 0; i < idx->hdr->cnt; i++) {
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

int show_status() {
    int fcnt = 0;
    char** paths = NULL;
    collect_files(".", &paths, &fcnt);

    idx_t* idx = read_idx();
    if (!idx) {
        free_str_arr(paths, fcnt);
        return -1;
    }

    print_modified(paths, fcnt, idx);
    printf("\n");
    print_new(paths, fcnt, idx);
    printf("\n");
    print_deleted(paths, fcnt, idx);

    free_idx(idx);
    free_str_arr(paths, fcnt);
    return 0;
}

int write_idx(idx_t *idx) {
    int idx_size = HDR_SIZE;
    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        int path_len = strlen(idx->entries[i]->path);
        int entry_len = ((62 + path_len + 8) / 8) * 8;
        idx_size += entry_len;
    }
    idx_size += idx->ext_size;
    idx_size += 20; 

    uint8_t *index_data = calloc(idx_size, 1);

    memcpy(index_data, idx->hdr->sig, 4);
    uint32_t ver = htonl(idx->hdr->ver);
    memcpy(index_data + 4, &ver, 4);
    uint32_t cnt = htonl(idx->hdr->cnt);
    memcpy(index_data + 8, &cnt, 4);

    int p = HDR_SIZE;
    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        uint32_t ctime_s = htonl(idx->entries[i]->ctime_s);
        memcpy(index_data + p, &ctime_s, 4);

        uint32_t ctime_n = htonl(idx->entries[i]->ctime_n);
        memcpy(index_data + p + 4, &ctime_n, 4);

        uint32_t mtime_s = htonl(idx->entries[i]->mtime_s);
        memcpy(index_data + p + 8, &mtime_s, 4);

        uint32_t mtime_n = htonl(idx->entries[i]->mtime_n);
        memcpy(index_data + p + 12, &mtime_n, 4);

        uint32_t dev = htonl(idx->entries[i]->dev);
        memcpy(index_data + p + 16, &dev, 4);

        uint32_t ino = htonl(idx->entries[i]->ino);
        memcpy(index_data + p + 20, &ino, 4);

        uint32_t mode = htonl(idx->entries[i]->mode);
        memcpy(index_data + p + 24, &mode, 4);

        uint32_t uid = htonl(idx->entries[i]->uid);
        memcpy(index_data + p + 28, &uid, 4);

        uint32_t gid = htonl(idx->entries[i]->gid);
        memcpy(index_data + p + 32, &gid, 4);

        uint32_t fsize = htonl(idx->entries[i]->fsize);
        memcpy(index_data + p + 36, &fsize, 4);

        memcpy(index_data + p + 40, idx->entries[i]->sha1, SHA_DIGEST_LENGTH);

        uint16_t flags = htons(idx->entries[i]->flags);
        memcpy(index_data + p + 60, &flags, 2);

        strcpy((char*)(index_data + p + 62), idx->entries[i]->path);

        int path_len = strlen(idx->entries[i]->path);
        int entry_len = ((62 + path_len + 8) / 8) * 8;
        p += entry_len;
    }
    
    memcpy(index_data + p, idx->ext, idx->ext_size);

    SHA1(index_data, idx_size - 20, index_data + idx_size - 20);

    write_file(".git/index", index_data, idx_size, 0644);
    free(index_data);
    return 0;
}

int main() {
    printf("read before my write:\n");
    list_files(true);
    idx_t *idx = read_idx();
    if (!idx) exit(1);
    write_idx(idx);
    printf("\nread after my write:\n");
    list_files(true);
    free_idx(idx);
    return 0;
}
