#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h> 
#include <dirent.h>

#include <openssl/sha.h>
#include <zlib.h>

#define SIGNATURE_SIZE 4
#define VERSION_SIZE 4
#define ENTRY_COUNT_SIZE 4
#define INDEX_HEADER_SIZE (SIGNATURE_SIZE + VERSION_SIZE + ENTRY_COUNT_SIZE)

#define CTIME_S_SIZE 4
#define CTIME_N_SIZE 4
#define MTIME_S_SIZE 4
#define MTIME_N_SIZE 4
#define DEV_SIZE 4
#define INO_SIZE 4
#define MODE_SIZE 4
#define UID_SIZE 4
#define GID_SIZE 4
#define FILE_SIZE_SIZE 4
#define SHA1_SIZE SHA_DIGEST_LENGTH
#define FLAGS_SIZE 2

#define PATH_BUFFER_SIZE 4096
#define HEADER_BUFFER_SIZE 64

typedef struct {
    char signature[SIGNATURE_SIZE];     
    uint32_t version;     
    uint32_t entry_count; 
} index_header_t;

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
    uint32_t file_size;              
    uint8_t sha1[SHA_DIGEST_LENGTH];
    uint16_t flags;                
    char* path;             
} index_entry_t;

typedef struct {
    index_entry_t **entries;
    size_t size;
} index_entries_t;

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

bool directory_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

void create_directory(const char *dir) {
    if (mkdir(dir, 0775) != 0) {
        handle_error("mkdir error");
    }
}

void print_sha1_hash(const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        printf("%02x", sha1[i]);
    }
}

void free_string_array(char **array, int count) {
    for (int i = 0; i < count; i++) {
        free(array[i]);
    }
    free(array);
}

void free_index_entry(index_entry_t *entry) {
    if (entry) {
        free(entry->path);
        free(entry);
    }
}

void free_index_entries(index_entries_t *entries) {
    if (!entries) return;
    
    for (size_t i = 0; i < entries->size; i++) {
        free_index_entry(entries->entries[i]);
    }
    free(entries->entries);
    free(entries);
}

int read_file_data(const char* path, unsigned char** data, int* data_size) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open error");
        return -1;
    }

    int file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("lseek error");
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);

    unsigned char* file_data = malloc(file_size);
    if (!file_data) {
        close(fd);
        return -1;
    }

    int read_bytes = read(fd, file_data, file_size);
    if (read_bytes != file_size) {
        perror("read error");
        free(file_data);
        close(fd);
        return -1;
    }

    *data_size = file_size;
    *data = file_data;
    close(fd);
    return 0;
}

int write_file_data(const char* path, const unsigned char* data, size_t size, int mode) {
    int fd = open(path, O_CREAT | O_RDWR, mode);
    if (fd == -1) {
        handle_error("open error");
    }
    
    ssize_t written = write(fd, data, size);
    close(fd);
    
    return (written == (ssize_t)size) ? 0 : -1;
}

void initialize_repository() {
    create_directory(".git");
    create_directory(".git/objects");
    create_directory(".git/refs");
    create_directory(".git/refs/heads");

    const char *head_content = "ref: refs/heads/main";
    write_file_data(".git/HEAD", (const unsigned char*)head_content, strlen(head_content), 0664);

    printf("initialized empty repository\n");
}

unsigned char* create_git_object_data(const unsigned char* data, size_t data_size, 
                                            const char* type, size_t* total_size) {
    char header[HEADER_BUFFER_SIZE] = {0};
    snprintf(header, sizeof(header), "%s %zu", type, data_size);
    
    size_t header_len = strlen(header);
    *total_size = header_len + data_size + 1;
    
    unsigned char* combined_data = calloc(*total_size, sizeof(char));
    if (!combined_data) return NULL;

    memcpy(combined_data, header, header_len);
    memcpy(combined_data + header_len + 1, data, data_size);
    
    return combined_data;
}

unsigned char* compute_sha1_hash(const unsigned char* data, size_t data_size) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(data, data_size, hash);

    unsigned char *result_hash = malloc(SHA_DIGEST_LENGTH);
    if (result_hash) {
        memcpy(result_hash, hash, SHA_DIGEST_LENGTH);
    }
    
    return result_hash;
}

void build_object_path(const unsigned char* hash, char* dir_path, char* obj_path) {
    snprintf(dir_path, 32, ".git/objects/%02x", hash[0]);
    snprintf(obj_path, 64, "%s/", dir_path);
    
    char* path_end = obj_path + strlen(obj_path);
    for (int i = 1; i < SHA_DIGEST_LENGTH; i++) {
        snprintf(path_end + (i-1)*2, 3, "%02x", hash[i]);
    }
}

bool compress_and_write_object(const unsigned char* data, size_t data_size, 
                                     const char* obj_path) {
    size_t compressed_len = data_size * 2;
    unsigned char* compressed = malloc(compressed_len);
    if (!compressed) return false;
    
    bool success = false;
    if (compress(compressed, &compressed_len, data, data_size) == Z_OK) {
        success = (write_file_data(obj_path, compressed, compressed_len, 0444) == 0);
    }
    
    free(compressed);
    return success;
}

bool write_object_to_disk(const unsigned char* object_data, size_t data_size,
                                const unsigned char* hash) {
    char dir_path[32];
    char obj_path[64];
    
    build_object_path(hash, dir_path, obj_path);
    
    if (!directory_exists(dir_path)) {
        create_directory(dir_path);
    }
    
    return compress_and_write_object(object_data, data_size, obj_path);
}

unsigned char* create_object_hash(const unsigned char* data, size_t data_size,
                                       const char* type, bool write_to_disk) {
    size_t total_size;
    unsigned char* object_data = create_git_object_data(data, data_size, type,
                                                        &total_size);
    if (!object_data) return NULL;

    unsigned char* hash = compute_sha1_hash(object_data, total_size);
    if (!hash) {
        free(object_data);
        return NULL;
    }

    if (write_to_disk) {
        write_object_to_disk(object_data, total_size, hash);
    }

    free(object_data);
    return hash;
}

// Index parsing
bool validate_index_header(const unsigned char* file_data, index_header_t* header) {
    memcpy(header->signature, file_data, SIGNATURE_SIZE);
    if (memcmp(header->signature, "DIRC", 4) != 0) {
        fprintf(stderr, "invalid index signature\n");
        return false;
    }

    header->version = ntohl(*(uint32_t*)(file_data + SIGNATURE_SIZE));
    if (header->version != 2) {
        fprintf(stderr, "invalid index version\n");
        return false;
    }

    header->entry_count = ntohl(*(uint32_t*)(file_data + SIGNATURE_SIZE + VERSION_SIZE));
    return true;
}

bool validate_index_checksum(const unsigned char* file_data, int file_size) {
    unsigned char computed_hash[SHA_DIGEST_LENGTH];
    SHA1(file_data, file_size - SHA_DIGEST_LENGTH, computed_hash);
    return memcmp(computed_hash, file_data + file_size - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) == 0;
}

index_entry_t* parse_index_entry(const unsigned char* data, int offset) {
    index_entry_t *entry = calloc(1, sizeof(index_entry_t));
    if (!entry) return NULL;

    const unsigned char* entry_data = data + offset;
    
    entry->ctime_s = ntohl(*(uint32_t*)(entry_data + 0));
    entry->ctime_n = ntohl(*(uint32_t*)(entry_data + 4));
    entry->mtime_s = ntohl(*(uint32_t*)(entry_data + 8));
    entry->mtime_n = ntohl(*(uint32_t*)(entry_data + 12));
    entry->dev = ntohl(*(uint32_t*)(entry_data + 16));
    entry->ino = ntohl(*(uint32_t*)(entry_data + 20));
    entry->mode = ntohl(*(uint32_t*)(entry_data + 24));
    entry->uid = ntohl(*(uint32_t*)(entry_data + 28));
    entry->gid = ntohl(*(uint32_t*)(entry_data + 32));
    entry->file_size = ntohl(*(uint32_t*)(entry_data + 36));
    
    memcpy(entry->sha1, entry_data + 40, SHA_DIGEST_LENGTH);
    entry->flags = ntohs(*(uint16_t*)(entry_data + 60));
    entry->path = strdup((char*)(entry_data + 62));

    return entry;
}

index_entries_t* read_index_file() {
    int file_size;
    unsigned char *file_data;
    
    if (read_file_data(".git/index", &file_data, &file_size) != 0) {
        return NULL;
    }

    if (!validate_index_checksum(file_data, file_size)) {
        fprintf(stderr, "invalid index checksum\n");
        free(file_data);
        return NULL;
    }

    index_header_t header;
    if (!validate_index_header(file_data, &header)) {
        free(file_data);
        return NULL;
    }

    index_entries_t *entries = calloc(1, sizeof(index_entries_t));
    if (!entries) {
        free(file_data);
        return NULL;
    }

    entries->entries = calloc(header.entry_count, sizeof(index_entry_t*));
    entries->size = header.entry_count;

    int offset = INDEX_HEADER_SIZE;
    for (uint32_t i = 0; i < header.entry_count; i++) {
        entries->entries[i] = parse_index_entry(file_data, offset);
        if (!entries->entries[i]) {
            free_index_entries(entries);
            free(file_data);
            return NULL;
        }
        
        // Calculate next entry offset (8-byte aligned)
        offset += ((62 + strlen(entries->entries[i]->path) + 8) / 8) * 8;
    }

    free(file_data);
    return entries;
}

// File listing
void list_files(bool show_details) {
    index_entries_t *entries = read_index_file();
    if (!entries) return;

    for (size_t i = 0; i < entries->size; i++) {
        index_entry_t *entry = entries->entries[i];
        if (show_details) {
            uint16_t stage = (entry->flags >> 12) & 0x3;
            printf("%06o ", entry->mode);
            print_sha1_hash(entry->sha1);
            printf(" %d\t%s\n", stage, entry->path);
        } else {
            printf("%s\n", entry->path);
        }
    }
    
    free_index_entries(entries);
}

// Directory traversal
void collect_directory_files(const char* base_path, char*** files_list, int* list_size) {
    const int initial_capacity = 16;
    int stack_capacity = initial_capacity;
    char **directory_stack = calloc(stack_capacity, sizeof(char*));
    directory_stack[0] = strdup(base_path);
    int stack_size = 1;

    int list_capacity = initial_capacity;
    *files_list = calloc(list_capacity, sizeof(char*));
    *list_size = 0;

    while (stack_size > 0) {
        stack_size--;
        char *current_dir = directory_stack[stack_size];
        DIR *dir = opendir(current_dir);
        
        if (!dir) {
            free(current_dir);
            continue;
        }

        struct dirent *entry;
        char path[PATH_BUFFER_SIZE] = {0}; 
        
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (strcmp(current_dir, ".") != 0) {
                snprintf(path, sizeof(path), "%s/%s", current_dir, entry->d_name);
            } else {
                snprintf(path, sizeof(path), "%s", entry->d_name);
            }

            struct stat file_stat;
            if (stat(path, &file_stat) == -1) {
                continue;
            }

            if (S_ISDIR(file_stat.st_mode)) {
                if (strcmp(entry->d_name, ".git") != 0) {
                    if (stack_size >= stack_capacity) {
                        stack_capacity *= 2;
                        directory_stack = realloc(directory_stack, stack_capacity * sizeof(char*));
                    }
                    directory_stack[stack_size] = strdup(path);
                    stack_size++;
                }
            } else {
                if (*list_size >= list_capacity) {
                    list_capacity *= 2;
                    *files_list = realloc(*files_list, list_capacity * sizeof(char*));
                }
                (*files_list)[*list_size] = strdup(path);
                (*list_size)++;
            }
        }
        
        free(current_dir);
        closedir(dir);
    }
    
    free(directory_stack);
}

// Status checking functions
void print_modified_files(char **file_paths, int path_count, index_entries_t* index_entries) {
    bool header_printed = false;
    
    for (int i = 0; i < path_count; i++) {
        for (size_t j = 0; j < index_entries->size; j++) {
            if (strcmp(file_paths[i], index_entries->entries[j]->path) != 0) {
                continue;
            }

            int data_size;
            unsigned char *file_data;
            if (read_file_data(file_paths[i], &file_data, &data_size) != 0) {
                continue;
            }

            unsigned char* file_hash = create_object_hash(file_data, data_size, "blob", false);
            bool is_modified = memcmp(file_hash, index_entries->entries[j]->sha1, SHA_DIGEST_LENGTH) != 0;

            if (is_modified) {
                if (!header_printed) {
                    printf("  modified files:\n");
                    header_printed = true;
                }
                printf("    %s\n", file_paths[i]);
            }

            free(file_hash);
            free(file_data);
            break;
        }
    }
}

void print_new_files(char **file_paths, int path_count, index_entries_t* index_entries) {
    bool header_printed = false;
    
    for (int i = 0; i < path_count; i++) {
        bool found_in_index = false;
        
        for (size_t j = 0; j < index_entries->size; j++) {
            if (strcmp(file_paths[i], index_entries->entries[j]->path) == 0) {
                found_in_index = true;
                break; 
            }
        }
        
        if (!found_in_index) {
            if (!header_printed) {
                printf("  new files:\n");
                header_printed = true;
            }
            printf("    %s\n", file_paths[i]);
        }
    }
}

void print_deleted_files(char **file_paths, int path_count, index_entries_t* index_entries) {
    bool header_printed = false;
    
    for (size_t i = 0; i < index_entries->size; i++) {
        bool found_in_filesystem = false;
        
        for (int j = 0; j < path_count; j++) {
            if (strcmp(index_entries->entries[i]->path, file_paths[j]) == 0) {
                found_in_filesystem = true;
                break;
            }
        }
        
        if (!found_in_filesystem) {
            if (!header_printed) {
                printf("  deleted files:\n");
                header_printed = true;
            }
            printf("    %s\n", index_entries->entries[i]->path);
        }
    }
}

void show_repository_status() {
    int file_count = 0;
    char** file_paths = NULL;
    collect_directory_files(".", &file_paths, &file_count);
    
    index_entries_t* index_entries = read_index_file();
    if (!index_entries) {
        free_string_array(file_paths, file_count);
        return;
    }

    print_modified_files(file_paths, file_count, index_entries);
    printf("\n");
    print_new_files(file_paths, file_count, index_entries);
    printf("\n");
    print_deleted_files(file_paths, file_count, index_entries);

    free_index_entries(index_entries);
    free_string_array(file_paths, file_count);
}

int main() {
    show_repository_status();
    return 0;
}
