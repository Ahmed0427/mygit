#ifndef OBJECTS_H
#define OBJECTS_H

unsigned char* hash_obj(const unsigned char* data, size_t data_size,
                        const char* type, bool write_to_disk);

char* get_obj_data(char* hash);

void cat_file(char* hash);

char** collect_commit_files(int* cnt);

#endif
