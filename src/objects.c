#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "objects.h"
#include "utils.h"

#define HDR_BUF_SIZE 64

typedef struct {
    char* mode;
    char* type;
    char* hash;
    char* name;
} tree_entry_t;

typedef struct {
    tree_entry_t* entries;
    int count;
} tree_t;

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

        snprintf(dir_path, sizeof(dir_path), ".git/objects/%02x", result_hash[0]);
        snprintf(obj_path, sizeof(obj_path), "%s/%02x", dir_path, result_hash[1]);

        char hex_suffix[40] = {0};
        for (int i = 2; i < SHA_DIGEST_LENGTH; i++) {
            snprintf(hex_suffix + (i - 2) * 2, 3, "%02x", result_hash[i]);
        }
        strncat(obj_path, hex_suffix, sizeof(obj_path) - strlen(obj_path) - 1);

        if (!dir_exists(dir_path)) {
            mk_dir(dir_path);
        }
        if (file_exists(obj_path)) {
            free(combined_data);
            return result_hash;
        }

        size_t compressed_len = compressBound(total_size);
        unsigned char* compressed = calloc(compressed_len, 1);
        if (compressed) {
            int comp_status = compress(compressed, &compressed_len,
                               combined_data, total_size);
            if (comp_status == Z_OK) {
                write_file(obj_path, compressed, compressed_len, 0444);
            } else {
                fprintf(stderr, "Compression failed: %d\n", comp_status);
            }
            free(compressed);
        } else {
            fprintf(stderr, "calloc for compression buffer failed\n");
        }
    }

    free(combined_data);
    return result_hash;
}

char* get_obj_data(char* hash) {
    assert(hash != NULL);
    if (strlen(hash) != 40) {
        return NULL;
    }

    char obj_path[64] = {0};
    strcat(obj_path, ".git/objects/");
    strncat(obj_path, hash, 2);
    strcat(obj_path, "/");
    strncat(obj_path, hash + 2, 38);

    if (!file_exists(obj_path)) {
        return NULL;
    }

    unsigned char* zdata = NULL;
    int zdata_sz = 0;

    if (read_file(obj_path, &zdata, &zdata_sz) != 0) {
        fprintf(stderr, "Failed to read object file\n");
        exit(1);
    }

    assert(zdata != NULL);
    assert(zdata_sz > 0);

    uLongf data_sz = zdata_sz * 5;
    char* data = malloc(data_sz);
    if (!data) {
        perror("malloc for decompressed data");
        free(zdata);
        exit(1);
    }

    int res = uncompress((Bytef*)data, &data_sz, zdata, zdata_sz);
    if (res != Z_OK) {
        fprintf(stderr, "Decompression failed: %d\n", res);
        free(data);
        free(zdata);
        exit(1);
    }

    free(zdata);  
    return data;
}

tree_t* parse_tree_entries(char* content, int size) {
    const char* p = content;
    const char* end = content + size;

    int capacity = 8;
    int count = 0;

    tree_entry_t* entries = malloc(capacity * sizeof(tree_entry_t));
    if (!entries) return NULL;

    while (p < end) {
        const char* mode_end = memchr(p, ' ', end - p);
        if (!mode_end) break;

        int mode_len = mode_end - p;
        char* mode = strndup(p, mode_len);
        p = mode_end + 1;

        const char* name_end = memchr(p, '\0', end - p);
        if (!name_end || name_end + 20 > end) {
            free(mode);
            break;
        }

        int name_len = name_end - p;
        char* name = strndup(p, name_len);
        p = name_end + 1;

        char* hash = sha1_to_hex((const uint8_t*)p);
        p += 20;

        char* data = get_obj_data(hash);
        assert(data != NULL);

        char* type = strtok(data, " ");
        if (!type) {
            free(data);
            free(mode);
            free(name);
            free(hash);
            break;
        }

        if (count >= capacity) {
            capacity *= 2;
            tree_entry_t* tmp = realloc(entries, capacity * sizeof(tree_entry_t));
            if (!tmp) {
                free(mode);
                free(name);
                free(hash);
                free(data);
                break;
            }
            entries = tmp;
        }

        entries[count].mode = mode;
        entries[count].type = strdup(type);
        entries[count].hash = hash;
        entries[count].name = name;
        count++;

        free(data);
    }

    tree_t* tree = malloc(sizeof(tree_t));
    if (!tree) {
        for (int i = 0; i < count; i++) {
            free(entries[i].mode);
            free(entries[i].type);
            free(entries[i].hash);
            free(entries[i].name);
        }
        free(entries);
        return NULL;
    }

    tree->entries = entries;
    tree->count = count;
    return tree;
}

void free_tree(tree_t* tree) {
    for (int i = 0; i < tree->count; i++) {
        free(tree->entries[i].mode);
        free(tree->entries[i].type);
        free(tree->entries[i].hash);
        free(tree->entries[i].name);
    }
    free(tree->entries);
    free(tree);
}

void print_tree(const tree_t* tree) {
    for (int i = 0; i < tree->count; i++) {
        for (int j = strlen(tree->entries[i].mode); j < 6; j++) {
            printf("0");
        }
        printf("%s %s %s    %s\n",
            tree->entries[i].mode,
            tree->entries[i].type,
            tree->entries[i].hash,
            tree->entries[i].name);
    }
}

void cat_file(char* hash) {
    char* data = get_obj_data(hash);
    if (data == NULL) {
        fprintf(stderr, "ERROR: Not a valid object name %s", hash);
        assert(false);
    }

    char *type = strtok(data, " "); 
    char *size_str = strtok(NULL, " ");
    printf("type: %s\n", type);
    printf("size: %s\n", size_str);
    printf("\n");

    char* content = data + strlen(type) + strlen(size_str) + 2;
    
    if (strcmp(type, "tree") == 0) {
        tree_t* tree = parse_tree_entries(content, atoi(size_str));
        print_tree(tree);
        free_tree(tree);

    } else {
        printf("%s", content);
    }

    free(data);
    printf("\n");

}

char** collect_tree_files(char* tree_hash, int* cnt) {
    int stk_cap = 8, stk_sz = 0;
    char** stk = malloc(stk_cap * sizeof(char*));
    if (!stk) return NULL;

    int lst_cap = 8, lst_sz = 0;
    char** files = malloc(lst_cap * sizeof(char*));
    if (!files) {
        free(stk);
        return NULL;
    }

    char entry_buf[PATH_BUF_SIZE];
    snprintf(entry_buf, sizeof(entry_buf), ". %s", tree_hash);
    stk[stk_sz++] = strdup(entry_buf);

    while (stk_sz > 0) {
        char* path_hash = stk[--stk_sz];
        char* path = strtok(path_hash, " ");
        char* hash = strtok(NULL, " ");
        if (!path || !hash) {
            fprintf(stderr, "ERROR: Malformed path/hash entry: %s\n", path_hash);
            free(path_hash);
            continue;
        }

        char* data = get_obj_data(hash);
        if (!data) {
            fprintf(stderr, "ERROR: Not a valid object name %s\n", hash);
            free(path_hash);
            continue;
        }

        char* type = strtok(data, " ");
        char* size_str = strtok(NULL, " ");
        if (!type || !size_str) {
            fprintf(stderr, "ERROR: Malformed object data\n");
            free(data);
            free(path_hash);
            continue;
        }

        char* content = data + strlen(type) + strlen(size_str) + 2;
        if (strcmp(type, "tree") != 0) {
            fprintf(stderr, "ERROR: Expected tree object, got %s\n", type);
            free(data);
            free(path_hash);
            continue;
        }

        tree_t* tree = parse_tree_entries(content, atoi(size_str));
        free(data);

        for (int i = 0; i < tree->count; i++) {
            tree_entry_t ent = tree->entries[i];

            if (strcmp(path, ".") == 0) {
                snprintf(entry_buf, sizeof(entry_buf), "%s", ent.name);
            } else {
                snprintf(entry_buf, sizeof(entry_buf), "%s/%s", path, ent.name);
            }

            char buf[PATH_BUF_SIZE * 2];
            snprintf(buf, sizeof(buf), "%s %s", entry_buf, ent.hash);

            if (strcmp(ent.type, "tree") == 0) {
                if (stk_sz >= stk_cap) {
                    stk_cap *= 2;
                    char** new_stk = realloc(stk, stk_cap * sizeof(char*));
                    if (!new_stk) {
                        free_tree(tree);
                        free(path_hash);
                        goto fail;
                    }
                    stk = new_stk;
                }
                stk[stk_sz++] = strdup(buf);
            } else {
                if (lst_sz >= lst_cap) {
                    lst_cap *= 2;
                    char** new_files = realloc(files, lst_cap * sizeof(char*));
                    if (!new_files) {
                        free_tree(tree);
                        free(path_hash);
                        goto fail;
                    }
                    files = new_files;
                }
                files[lst_sz++] = strdup(buf);
            }
        }

        free_tree(tree);
        free(path_hash);
    }

    free(stk);
    *cnt = lst_sz;
    return files;

fail:
    for (int i = 0; i < lst_sz; i++) free(files[i]);
    for (int i = 0; i < stk_sz; i++) free(stk[i]);
    free(files);
    free(stk);
    *cnt = 0;
    return NULL;
}

char** collect_commit_files(int* cnt) {
    char* main_hash = NULL;
    int commit_hash_size = 0;
    int ret = read_file(".git/refs/heads/main",
            (unsigned char**)&main_hash, &commit_hash_size);

    if (ret != 0 || !main_hash) return NULL;
    assert(strlen(main_hash) >= 40);
    char* commit_hash = calloc(45, 1);
    memcpy(commit_hash, main_hash, 40);

    char* commit_data = get_obj_data(commit_hash);
    if (!commit_data) return NULL;
    *(strchr(commit_data + 16, '\n')) = '\0';
    char* tree_hash = commit_data + 16;

    char** entries = collect_tree_files(tree_hash, cnt);
    free(commit_data);
    free(commit_hash);

    return entries;
}
