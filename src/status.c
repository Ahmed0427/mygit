#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "status.h"
#include "objects.h"
#include "utils.h"
#include "index.h"

char** get_modified_files(char** paths, int pcnt, idx_t* idx, int* out_count) {
    char** result = malloc(sizeof(char*) * pcnt);  
    int count = 0;

    for (int i = 0; i < pcnt; i++) {
        for (size_t j = 0; j < idx->hdr->cnt; j++) {
            if (strcmp(paths[i], idx->entries[j]->path) != 0)
                continue;

            int size;
            unsigned char* data;
            if (read_file(paths[i], &data, &size) != 0)
                break;

            unsigned char* hash = hash_obj(data, size, "blob", false);
            bool mod = memcmp(hash, idx->entries[j]->sha1, SHA_DIGEST_LENGTH) != 0;

            if (mod) {
                result[count++] = strdup(paths[i]);
            }

            free(hash);
            free(data);
            break;
        }
    }

    *out_count = count;
    return result;
}

char** get_new_files(char** paths, int pcnt, idx_t* idx, int* out_count) {
    char** result = malloc(sizeof(char*) * pcnt);
    int count = 0;

    for (int i = 0; i < pcnt; i++) {
        bool found = false;
        for (size_t j = 0; j < idx->hdr->cnt; j++) {
            if (strcmp(paths[i], idx->entries[j]->path) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            result[count++] = strdup(paths[i]);
        }
    }

    *out_count = count;
    return result;
}

char** get_deleted_files(char** paths, int pcnt, idx_t* idx, int* out_count) {
    char** result = malloc(sizeof(char*) * idx->hdr->cnt);
    int count = 0;

    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        bool found = false;
        for (int j = 0; j < pcnt; j++) {
            if (strcmp(idx->entries[i]->path, paths[j]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            result[count++] = strdup(idx->entries[i]->path);
        }
    }

    *out_count = count;
    return result;
}

void print_red(const char* str) {
    printf("\033[0;31m%s\033[0m", str);
}

void print_green(const char* str) {
    printf("\033[1;32m%s\033[0m", str);
}

void print_staged_changes(idx_t* idx) {
    int entries_cnt = 0;
    char** entries = collect_commit_files(&entries_cnt);          
    for (int i = 0; i < entries_cnt; i++) {
        printf("%s\n", entries[i]);
    }
    printf("\n");
    for (int i = 0; i < (int)idx->hdr->cnt; i++) {
        printf("%s ", idx->entries[i]->path);
        char* hash = sha1_to_hex(idx->entries[i]->sha1);
        printf("%s\n", hash);
        free(hash);
    }
    if (idx) return;
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

    int mod_size, new_size, del_size; 
    char** mod_list = get_modified_files(paths, fcnt, idx, &mod_size);
    char** new_list = get_new_files(paths, fcnt, idx, &new_size);
    char** del_list = get_deleted_files(paths, fcnt, idx, &del_size);


    print_staged_changes(idx);

    // if (mod_size || del_size) {
    //     printf("Changes not staged for commit:\n");
    //     for (int i = 0; i < mod_size; i++) {
    //         printf("    ");
    //         print_red("modified: ");
    //         print_red(mod_list[i]);
    //         printf("\n");
    //     }
    //     for (int i = 0; i < del_size; i++) {
    //         printf("    ");
    //         print_red("deleted: ");
    //         print_red(del_list[i]);
    //         printf("\n");
    //     }
    // }
    //
    // if (new_size) {
    //     printf("\nUntracked files:\n");
    //     for (int i = 0; i < new_size; i++) {
    //         printf("    ");
    //         print_red(new_list[i]);
    //         printf("\n");
    //     }
    // }

    free_idx(idx);
    free_str_arr(paths, fcnt);
    free_str_arr(mod_list, mod_size);
    free_str_arr(new_list, new_size);
    free_str_arr(del_list, del_size);
    return 0;
}
