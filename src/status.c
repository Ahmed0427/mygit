#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "status.h"
#include "objects.h"
#include "utils.h"
#include "index.h"

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

