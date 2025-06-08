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

#include <openssl/sha.h>
#include <zlib.h>

typedef struct {
    char signature[4];     
    uint32_t version;     
    uint32_t entry_count; 
} index_header_t;

const int SIGNATURE_SIZE = 4;
const int VERSION_SIZE = 4;
const int ENTRY_COUNT_SIZE = 4;
const int INDEX_HEADER_SIZE = SIGNATURE_SIZE + VERSION_SIZE + ENTRY_COUNT_SIZE;

const int SIGNATURE_OFFSET = 0;
const int VERSION_OFFSET = SIGNATURE_OFFSET + SIGNATURE_SIZE;
const int ENTRY_COUNT_OFFSET = VERSION_OFFSET + VERSION_SIZE;

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

const int CTIME_S_SIZE = 4;
const int CTIME_N_SIZE = 4;
const int MTIME_S_SIZE = 4;
const int MTIME_N_SIZE = 4;
const int DEV_SIZE = 4;
const int INO_SIZE = 4;
const int MODE_SIZE = 4;
const int UID_SIZE = 4;
const int GID_SIZE = 4;
const int FILE_SIZE_SIZE = 4;
const int SHA1_SIZE = SHA_DIGEST_LENGTH; 
const int FLAGS_SIZE = 2;

const int CTIME_S_OFFSET = 0;
const int CTIME_N_OFFSET = CTIME_S_OFFSET + CTIME_S_SIZE;
const int MTIME_S_OFFSET = CTIME_N_OFFSET + CTIME_N_SIZE;
const int MTIME_N_OFFSET = MTIME_S_OFFSET + MTIME_S_SIZE;
const int DEV_OFFSET = MTIME_N_OFFSET + MTIME_N_SIZE;
const int INO_OFFSET = DEV_OFFSET + DEV_SIZE;
const int MODE_OFFSET = INO_OFFSET + INO_SIZE;
const int UID_OFFSET = MODE_OFFSET + MODE_SIZE;
const int GID_OFFSET = UID_OFFSET + UID_SIZE;
const int FILE_SIZE_OFFSET = GID_OFFSET + GID_SIZE;
const int SHA1_OFFSET = FILE_SIZE_OFFSET + FILE_SIZE_SIZE;
const int FLAGS_OFFSET = SHA1_OFFSET + SHA1_SIZE;
const int PATH_OFFSET = FLAGS_OFFSET + FLAGS_SIZE;

typedef struct {
    index_entry_t **entries;
    size_t size;
} index_entries_t;

void free_index_entries(index_entries_t *entries) {
    for (int i = 0; i < (int)entries->size; i++) {
        free(entries->entries[i]->path);
        free(entries->entries[i]);
    }
    free(entries->entries);
    free(entries);
}

void print_sha1(const uint8_t sha1[SHA_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        printf("%02x", sha1[i]);
    }
}

bool is_dir_exist(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

void mkdir_handle_err(const char *dir) {
    int ret = mkdir(dir, 0775);
    if (ret != 0) {
        perror("mkdir error");
        exit(1);
    }
}

void init_repo() {
    mkdir_handle_err(".git");
    mkdir_handle_err(".git/objects");
    mkdir_handle_err(".git/refs");
    mkdir_handle_err(".git/refs/heads");

    int fd = open(".git/HEAD", O_CREAT | O_RDWR, 0664);
    if (fd == -1) {
        perror("open error");
        exit(1);
    }
    char *head_content = "ref: refs/heads/main";
    write(fd, head_content, strlen(head_content));
    close(fd);

    printf("initialized empty repository\n");
}

char *hash_object(char* data, size_t data_size, char* type, bool write_flag) {
    char header[64] = {0};
    sprintf(header, "%s %zu", type, data_size);
    size_t all_data_size = strlen(header) + data_size + 1;
    unsigned char* all_data = calloc(all_data_size, sizeof(char));
    memcpy(all_data, header, strlen(header));
    memcpy(all_data + strlen(header) + 1, data, data_size);

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(all_data, all_data_size, hash);

    char *sha1 = calloc(2 * SHA_DIGEST_LENGTH + 1, sizeof(char));
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(sha1 + i * 2, "%02x", hash[i]);
    }
    if (write_flag) {
        char dir_path[16];
        char obj_path[16 + 38];
        sprintf(dir_path, "%s/%s/%c%c", ".git", "objects", sha1[0], sha1[1]);
        sprintf(obj_path, "%s/%s", dir_path, sha1 + 2);
        printf("%s\n", sha1);
        printf("%s\n", obj_path);
        if (!is_dir_exist(dir_path)) {
            mkdir_handle_err(dir_path);
        }
        size_t compressed_len = all_data_size * 2;
        unsigned char* compressed = calloc(compressed_len, sizeof(char));
        compress(compressed, &compressed_len, all_data, all_data_size);
        compressed = realloc(compressed, compressed_len);
        int fd = open(obj_path, O_CREAT | O_RDWR, 0444);
        if (fd == -1) {
            perror("open error");
            exit(1);
        }
        write(fd, compressed, compressed_len);
        free(compressed);
    }
    free(all_data);
    all_data = NULL;
    return sha1;
}

index_entries_t* read_index() {
    int fd = open(".git/index", O_RDONLY);
    if (fd == -1) {
        perror("open error");
        return NULL;
    }

    int file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 20) {
        fprintf(stderr, "file too small to be a valid index\n");
        close(fd);
        return NULL;
    }
    lseek(fd, 0, SEEK_SET);

    unsigned char* file_data = malloc(file_size);
    int read_bytes = read(fd, file_data, file_size);
    if (read_bytes != file_size) {
        perror("read error");
        free(file_data);
        close(fd);
        return NULL;
    }

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(file_data, file_size - 20, hash);
    if (memcmp(hash, file_data + file_size - 20, 20) != 0) {
        fprintf(stderr, "invalid index checksum\n"); 
        return NULL;
    }

    index_header_t header;
    memcpy(header.signature, file_data, SIGNATURE_SIZE);
    if (memcmp(header.signature, "DIRC", 4) != 0) {
        fprintf(stderr, "invalid index signature\n"); 
        return NULL;
    }
    header.version = ntohl(*(uint32_t*)(file_data + VERSION_OFFSET));
    if (header.version != 2) {
        fprintf(stderr, "invalid index version\n"); 
        return NULL;
    }

    header.entry_count = ntohl(*(uint32_t*)(file_data + ENTRY_COUNT_OFFSET));

    index_entries_t *entries = calloc(1, sizeof(index_entries_t));
    entries->entries = calloc(header.entry_count, sizeof(index_entry_t*));
    entries->size = header.entry_count;

    int i = INDEX_HEADER_SIZE;
    uint32_t read_entries = 0;
    while (read_entries < header.entry_count) {
        index_entry_t *entry = calloc(1, sizeof(index_entry_t));
        entry->ctime_n = ntohl(*(uint32_t*)(file_data + CTIME_N_OFFSET + i));
        entry->ctime_s = ntohl(*(uint32_t*)(file_data + CTIME_S_OFFSET + i));
        entry->mtime_s = ntohl(*(uint32_t*)(file_data + MTIME_S_OFFSET + i));
        entry->mtime_n = ntohl(*(uint32_t*)(file_data + MTIME_N_OFFSET + i));
        entry->dev = ntohl(*(uint32_t*)(file_data + DEV_OFFSET + i));
        entry->ino = ntohl(*(uint32_t*)(file_data + INO_OFFSET + i));
        entry->mode = ntohl(*(uint32_t*)(file_data + MODE_OFFSET + i));
        entry->uid = ntohl(*(uint32_t*)(file_data + UID_OFFSET + i));
        entry->gid = ntohl(*(uint32_t*)(file_data + GID_OFFSET + i));
        entry->file_size = ntohl(*(uint32_t*)(file_data + FILE_SIZE_OFFSET + i));
        memcpy(entry->sha1, file_data + SHA1_OFFSET + i, SHA1_SIZE);
        entry->flags = ntohs(*(uint16_t*)(file_data + FLAGS_OFFSET + i));
        entry->path = strdup((char*)(file_data + PATH_OFFSET + i));

        i += ((62 + strlen(entry->path) + 8) / 8) * 8;

        entries->entries[read_entries] = entry;
        read_entries++;
    }

    free(file_data);
    close(fd);

    return entries;
}

void ls_files(index_entries_t *entries) {
    for (int i = 0; i < (int)entries->size; i++) {
        index_entry_t *entry = entries->entries[i];
        uint16_t stage = (entry->flags >> 12) & 0x3;
        printf("%06u ", entry->mode);
        print_sha1(entry->sha1);
        printf(" %d\t%s\n", stage, entry->path);
    }
}

int main() {
    index_entries_t *entries = read_index();
    ls_files(entries);
    free_index_entries(entries);
    entries = NULL;
    return 0;
}
