#include <stdbool.h>
#include <zlib.h>

#include "objects.h"
#include "utils.h"

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

