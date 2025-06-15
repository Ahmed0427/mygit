#ifndef INDEX_H
#define INDEX_H

#include <stdint.h>

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


void free_entry(idx_entry_t* e);
 
void free_entries(idx_entry_t** entries, size_t entries_size);

void free_idx(idx_t* idx);

idx_t* read_idx();

int list_files(bool details);

int write_idx(idx_t *idx);

int add_to_index(char** paths, size_t paths_cnt);

#endif 
