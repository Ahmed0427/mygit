#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h>

#include "index.h"
#include "utils.h"
#include "objects.h"

void free_entry(idx_entry_t* e) {
    if (e) {
        free(e->path);
        free(e);
    }
}

void free_entries(idx_entry_t** entries, size_t entries_size) {
    if (entries == NULL) return;
    for (size_t i = 0; i < entries_size; i++) {
        free_entry(entries[i]);
    }
    free(entries);
}

void free_idx(idx_t* idx) {
    if (!idx) return;
    free_entries(idx->entries, idx->hdr->cnt);
    if (idx->hdr) free(idx->hdr);
    if (idx->ext) free(idx->ext);
    free(idx);
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
    return memcmp(hash, data + size - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0;
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

int init_index_file() {
    int fd = open(".git/index", O_CREAT | O_RDWR, 0664);
    if (fd == -1) {
        fprintf(stderr, "'%s' failed to write: %s\n", ".git/index", strerror(errno));
        return -1;
    }

    uint8_t index_data[32] = {0};

    memcpy(index_data, "DIRC", 4);
    uint32_t ver = htonl(2);
    memcpy(index_data + 4, &ver, 4);
    uint32_t cnt = htonl(0);
    memcpy(index_data + 8, &cnt, 4);

    SHA1(index_data, 12, index_data + 12);

    ssize_t written = write(fd, index_data, 32);
    close(fd);

    return (written == 32) ? 0 : -1;
}

idx_t* read_idx() {
    int size;
    unsigned char* data;

    if (!file_exists(".git/index")) {
        if (init_index_file() == -1) {
            return NULL;
        }
    }
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

idx_entry_t* copy_entry(const idx_entry_t* src) {
    if (!src) return NULL;

    idx_entry_t* dst = malloc(sizeof(idx_entry_t));
    if (!dst) return NULL;

    *dst = *src;

    dst->path = strdup(src->path);
    if (!dst->path) {
        free(dst);
        return NULL;
    }

    return dst;
}

int add_to_index(char** paths, size_t paths_cnt) {
    idx_t *idx = read_idx();
    if (!idx) return -1;

    size_t entries_cap = 4, entries_size = 0;
    idx_entry_t** entries = malloc(entries_cap * sizeof(idx_entry_t*));
    if (!entries) {
        free_idx(idx);
        return -1;
    }

    for (size_t j = 0; j < idx->hdr->cnt; j++) {
        bool found = false;
        for (size_t i = 0; i < paths_cnt; i++) {
            if (strcmp(paths[i], idx->entries[j]->path) == 0) {
                found = true;
                break;
            }
        }
        if (found) continue;

        if (entries_size >= entries_cap) {
            entries_cap *= 2;
            idx_entry_t** tmp = realloc(entries, entries_cap * sizeof(idx_entry_t*));
            if (!tmp) {
                free_entries(entries, entries_size);
                free_idx(idx);
                return -1;
            }
            entries = tmp;
        }

        idx_entry_t* new_entry = copy_entry(idx->entries[j]);
        if (!new_entry) {
            free_entries(entries, entries_size);
            free_idx(idx);
            return -1;
        }
        entries[entries_size++] = new_entry;
    }

    for (size_t i = 0; i < paths_cnt; i++) {
        int data_size = 0;
        unsigned char *data = NULL;
        read_file(paths[i], &data, &data_size);

        unsigned char* raw_sha1 = hash_obj(data, data_size, "blob", true);

        struct stat st;
        stat(paths[i], &st);

        idx_entry_t *ent = malloc(sizeof(idx_entry_t));
        ent->ctime_s = st.st_ctime;
        ent->ctime_n = 0;
        ent->mtime_s = st.st_mtime;
        ent->mtime_n = 0;
        ent->dev = st.st_dev;
        ent->ino = st.st_ino;
        ent->mode = st.st_mode;
        ent->uid = st.st_uid;
        ent->gid = st.st_gid;
        ent->fsize = st.st_size;
        memcpy(ent->sha1, raw_sha1, SHA_DIGEST_LENGTH);
        ent->flags = (uint16_t)strlen(paths[i]);
        ent->path = strdup(paths[i]);
        free(raw_sha1);

        if (entries_size >= entries_cap) {
            entries_cap *= 2;
            idx_entry_t** tmp = realloc(entries, entries_cap * sizeof(idx_entry_t*));
            if (!tmp) {
                free(data);
                free_entries(entries, entries_size);
                free_idx(idx);
                return -1;
            }
            entries = tmp;
        }

        entries[entries_size++] = ent;
        free(data);
    }
    free_entries(idx->entries, idx->hdr->cnt);
    idx->hdr->cnt = entries_size;
    idx->entries = entries;
    write_idx(idx);
    free_idx(idx);
    return 0;
}
