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
        fprintf(stderr, "ERROR: Not a valid object name %s\n", hash);
        exit(1);
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

tree_t* parse_tree_entries(char* content) {
    char* p = content;
    int capacity = 8;
    int count = 0;

    tree_entry_t* entries = malloc(capacity * sizeof(tree_entry_t));
    if (!entries) return NULL;

    while (*p) {
        if (count >= capacity) {
            capacity *= 2;
            entries = realloc(entries, capacity * sizeof(tree_entry_t));
            if (!entries) return NULL;
        }

        char* mode = p;
        char* before_name = strchr(p, ' ');
        if (!before_name) break;
        *before_name = '\0';

        char* name = before_name + 1;
        char* before_hash = strchr(name, '\0');
        if (!before_hash) break;

        char* hash = sha1_to_hex((uint8_t*)before_hash + 1);
        char* data = get_obj_data(hash);
        if (!data) break;

        char* type = strtok(data, " ");
        if (!type) {
            free(data);
            break;
        }

        entries[count].mode = strdup(mode);
        entries[count].type = strdup(type);
        entries[count].hash = strdup(hash);
        entries[count].name = strdup(name);

        free(data);

        p = p + strlen(mode) + strlen(name) + 22;
        count++;
    }

    tree_t* tree = malloc(sizeof(tree_t));

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
        exit(1);
    }

    char *type = strtok(data, " "); 
    char *size_str = strtok(NULL, " ");
    printf("type: %s\n", type);
    printf("size: %s\n", size_str);
    printf("\n");

    char* content = data + strlen(type) + strlen(size_str) + 2;
    
    if (strcmp(type, "tree") == 0) {
        tree_t* tree = parse_tree_entries(content);
        print_tree(tree);
        free_tree(tree);

    } else {
        printf("%s", content);
    }

    free(data);
    printf("\n");

}

char** collect_tree_files(char* tree_hash, int* cnt) {
    int stk_cap = 8;
    char** stk = calloc(stk_cap, sizeof(char*));
    char* entry = calloc(strlen(tree_hash) + 3, 1);
    strcat(entry, ".");
    strcat(entry, " ");
    strcat(entry, tree_hash);
    stk[0] = strdup(entry);
    free(entry);
    int stk_sz = 1;

    int lst_cap = 8;
    char** files = calloc(lst_cap, sizeof(char*));
    int lst_sz = 0;

    while (stk_sz > 0) {
        stk_sz--;
        char* path_hash = stk[stk_sz];
        char* path = strtok(path_hash, " ");
        char* hash = strtok(NULL, " ");
        char* data = get_obj_data(hash);
        if (data == NULL) {
            fprintf(stderr, "ERROR: Not a valid object name %s", hash);
            exit(1);
        }

        char *type = strtok(data, " "); 
        char *size_str = strtok(NULL, " ");
        printf("type: %s\n", type);
        printf("size: %s\n", size_str);
        printf("\n");

        char* content = data + strlen(type) + strlen(size_str) + 2;

        assert(strcmp(type, "tree") == 0);

        tree_t* tree = parse_tree_entries(content);

        char npath[PATH_BUF_SIZE] = {0};
        for (int i = 0; i < tree->count; i++) {
            tree_entry_t ent = tree->entries[i];

            if (strcmp(path, ".") != 0) {
                snprintf(npath, sizeof(npath), "%s/%s", path, ent.name);
            } else {
                snprintf(npath, sizeof(npath), "%s", ent.name);
            }

            if (strcmp(ent.type, "tree") == 0) {
                if (stk_sz >= stk_cap) {
                    stk_cap *= 2;
                    stk = realloc(stk, stk_cap * sizeof(char*));
                }
                entry = calloc(strlen(npath) + strlen(ent.hash) + 2, 1);
                strcat(entry, npath);
                strcat(entry, " ");
                strcat(entry, ent.hash);
                stk[stk_sz] = strdup(entry);
                free(entry);
                stk_sz++;
            } else {
                printf("%s\n", npath);
                if (lst_sz >= lst_cap) {
                    lst_cap *= 2;
                    files = realloc(*files, lst_cap * sizeof(char*));
                }
                entry = calloc(strlen(npath) + strlen(ent.hash) + 2, 1);
                strcat(entry, npath);
                strcat(entry, " ");
                strcat(entry, ent.hash);
                files[lst_sz] = strdup(entry);
                printf("%s\n", files[lst_sz]);
                free(entry);
                lst_sz++;
            }
        }
        free(path_hash);
    }
    free(stk);
    *cnt = lst_sz;
    return files;
}

char** collect_commit_files(int* cnt) {
    char* commit_hash = NULL;
    int commit_hash_size = 0;
    int ret = read_file(".git/refs/heads/main",
            (unsigned char**)&commit_hash, &commit_hash_size);

    if (ret != 0 || !commit_hash) return NULL;
    assert(strlen(commit_hash) >= 40);
    commit_hash[40] = '\0';

    char* commit_data = get_obj_data(commit_hash);
    if (!commit_data) return NULL;
    *(strchr(commit_data + 16, '\n')) = '\0';
    char* tree_hash = commit_data + 16;

    char** entries = collect_tree_files(tree_hash, cnt);
    free(commit_data);
    free(commit_hash);

    return entries;
}
