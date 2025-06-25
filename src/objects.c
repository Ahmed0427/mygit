#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <zlib.h>

#include "objects.h"
#include "utils.h"

#define HDR_BUF_SIZE 64

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

void print_tree_entries(char* content) {
    char* p = content;

    while (*p) {
        char* mode = p;
        char* before_name = strchr(p, ' ');
        assert(before_name != NULL);
        *before_name = '\0';

        char* name = before_name + 1;
        char* before_hash = strchr(name, '\0');
        assert(before_hash != NULL);
        char* hash = (char*)sha1_to_hex((uint8_t*)before_hash + 1);

        char* data = get_obj_data(hash);
        assert(data != NULL);

        char *type = strtok(data, " "); 

        printf("%s %s %s    %s\n", mode, type, hash, name);

        p = p + strlen(mode) + strlen(name) + 22;
        free(data);
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
        print_tree_entries(content);         
    } else {
        printf("%s", content);
    }

    free(data);
    printf("\n");

}

char** collect_tree_files(char* tree_hash, int* cnt) {
    printf("%s\n", tree_hash);
    if (cnt) return NULL;
    return NULL;
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
