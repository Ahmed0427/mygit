#ifndef STATUS_H
#define STATUS_H

#include "index.h"

char** get_modified_files(char** paths, int pcnt, idx_t* idx, int* out_count);
char** get_new_files(char** paths, int pcnt, idx_t* idx, int* out_count);
char** get_deleted_files(char** paths, int pcnt, idx_t* idx, int* out_count);

int show_status();

#endif
