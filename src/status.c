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

char** get_modified_files_staged(char** entries, int ecnt, idx_t* idx, int* out_cnt) {
    char** result = malloc(sizeof(char*) * ecnt);  
    int cnt = 0;

    for (int i = 0; i < ecnt; i++) {
        char* space = strchr(entries[i], ' ');
        if (!space) continue;
        int path_len = space - entries[i];

        for (size_t j = 0; j < idx->hdr->cnt; j++) {
            if (strncmp(entries[i], idx->entries[j]->path, path_len) == 0 &&
                idx->entries[j]->path[path_len] == '\0') {
                
                const char* hash = space + 1;
                char* idx_hash = sha1_to_hex(idx->entries[j]->sha1);
                
                if (strcmp(hash, idx_hash) != 0) {
                    result[cnt++] = strndup(entries[i], path_len);
                }

                free(idx_hash);
                break;
            }
        }
    }

    *out_cnt = cnt;
    return result;
}

char** get_deleted_files_staged(char** entries, int ecnt, idx_t* idx, int* out_cnt) {
    char** result = malloc(sizeof(char*) * ecnt);
    int cnt = 0;

    for (int i = 0; i < ecnt; i++) {
        char* space = strchr(entries[i], ' ');
        if (!space) continue;
        int path_len = space - entries[i];

        bool found = false;
        for (size_t j = 0; j < idx->hdr->cnt; j++) {
            if (strncmp(entries[i], idx->entries[j]->path, path_len) == 0 &&
                idx->entries[j]->path[path_len] == '\0') {
                found = true;
                break;
            }
        }

        if (!found) {
            result[cnt++] = strndup(entries[i], path_len);
        }
    }

    *out_cnt = cnt;
    return result;
}

char** get_new_files_staged(char** entries, int ecnt, idx_t* idx, int* out_cnt) {
    char** result = malloc(sizeof(char*) * idx->hdr->cnt);
    int cnt = 0;

    for (size_t i = 0; i < idx->hdr->cnt; i++) {
        bool found = false;

        for (int j = 0; j < ecnt; j++) {
            char* space = strchr(entries[j], ' ');
            if (!space) continue;
            int path_len = space - entries[j];

            if (strncmp(entries[j], idx->entries[i]->path, path_len) == 0 &&
                idx->entries[i]->path[path_len] == '\0') {
                found = true;
                break;
            }
        }

        if (!found) {
            result[cnt++] = strdup(idx->entries[i]->path);
        }
    }

    *out_cnt = cnt;
    return result;
}

void print_red(const char* str) {
    printf("\033[0;31m%s\033[0m", str);
}

void print_green(const char* str) {
    printf("\033[0;32m%s\033[0m", str);
}

int print_staged_changes(idx_t* idx) {
    int entries_cnt = 0;
    char** entries = collect_commit_files(&entries_cnt);          
    if (!entries) entries_cnt = 0;

    int mod_size = 0, new_size = 0, del_size = 0; 
    char** mod_list = get_modified_files_staged(entries, entries_cnt, idx, &mod_size);
    char** new_list = get_new_files_staged(entries, entries_cnt, idx, &new_size);
    char** del_list = get_deleted_files_staged(entries, entries_cnt, idx, &del_size);
    int cnt_all = mod_size + new_size + del_size;

    if (cnt_all) {
        printf("Changes to be committed:\n");
        for (int i = 0; i < mod_size; i++) {
            printf("    ");
            print_green("modified: ");
            print_green(mod_list[i]);
            printf("\n");
        }
        for (int i = 0; i < new_size; i++) {
            printf("    ");
            print_green("new file: ");
            print_green(new_list[i]);
            printf("\n");
        }
        for (int i = 0; i < del_size; i++) {
            printf("    ");
            print_green("deleted: ");
            print_green(del_list[i]);
            printf("\n");
        }
    }

    free_str_arr(mod_list, mod_size);
    free_str_arr(new_list, new_size);
    free_str_arr(del_list, del_size);
    free_str_arr(entries, entries_cnt);

    return cnt_all;
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


    int staged_size = print_staged_changes(idx);

    if (mod_size || del_size) {
        printf("Changes not staged for commit:\n");
        for (int i = 0; i < mod_size; i++) {
            printf("    ");
            print_red("modified: ");
            print_red(mod_list[i]);
            printf("\n");
        }
        for (int i = 0; i < del_size; i++) {
            printf("    ");
            print_red("deleted: ");
            print_red(del_list[i]);
            printf("\n");
        }
    }

    if (new_size) {
        printf("\nUntracked files:\n");
        for (int i = 0; i < new_size; i++) {
            printf("    ");
            print_red(new_list[i]);
            printf("\n");
        }
    }

    if (!staged_size && !mod_size && !del_size && !new_size) {
        printf("nothing to commit, working tree clean\n");
    }

    free_idx(idx);
    free_str_arr(paths, fcnt);
    free_str_arr(mod_list, mod_size);
    free_str_arr(new_list, new_size);
    free_str_arr(del_list, del_size);
    return 0;
}
