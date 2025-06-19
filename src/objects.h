#ifndef OBJECTS_H
#define OBJECTS_H

#define HDR_BUF_SIZE 64

unsigned char* hash_obj(const unsigned char* data, size_t data_size,
                        const char* type, bool write_to_disk);

void cat_file(char* hash);

#endif
