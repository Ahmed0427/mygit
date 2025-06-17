#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "index.h"
#include "status.h"
#include "commit.h"

#define PATH_BUF_SIZE 4096

void init_repo() {
    mk_dir(".git");
    mk_dir(".git/objects");
    mk_dir(".git/refs");
    mk_dir(".git/refs/heads");

    const char* head = "ref: refs/heads/main";
    write_file(".git/HEAD", (const unsigned char*)head, strlen(head), 0664);

    printf("initialized empty repository\n");
}

void help_msg() {
    printf("init      Create an empty Git repository\n");
    printf("ls-files  Prints all files in the index (use -s for details)\n");
    printf("status    Compare the files in the index and directory tree\n");
    printf("add       Add file contents to the index\n");
}

int main(int argc, char** argv) {
    if (argc == 1) {
        help_msg();
    } else if (strcmp(argv[1], "help") == 0) {
        if (argc > 2) {
            fprintf(stderr, "ERROR: too many args\n");
            exit(1);
        } else {
            help_msg();
        }
    } else if (strcmp(argv[1], "init") == 0) {
        if (argc > 2) {
            fprintf(stderr, "ERROR: too many args\n");
            exit(1);
        } else {
            init_repo();
        }
    } else if (strcmp(argv[1], "ls-files") == 0) {
        if (argc > 3) {
            fprintf(stderr, "ERROR: too many args\n");
            exit(1);
        } else if (argc == 3) {
            if (strcmp(argv[2], "-s") != 0) {
                fprintf(stderr, "ERROR: unknown flag '%s'\n", argv[2]);
                exit(1);
            }
            list_files(true);

        } else {
            list_files(false);
        }
    } else if (strcmp(argv[1], "status") == 0) {
        if (argc > 2) {
            fprintf(stderr, "ERROR: too many args\n");
            exit(1);
        } else {
            show_status();
        }
    } else if (strcmp(argv[1], "add") == 0) {
        for (int i = 2; i < argc; i++) {
            if (dir_exists(argv[i])) {
                int cnt = 0;
                char **paths = NULL;
                collect_files(argv[i], &paths, &cnt);
                add_to_index(paths, cnt);
            } else if (file_exists(argv[i])) {
                char* paths[] = {argv[i]}; 
                add_to_index(paths, 1);
            } else {
                fprintf(stderr, "ERROR: file '%s' doesn't exit\n", argv[i]);
            }
        }
    } else if (strcmp(argv[1], "commit") == 0) {
        write_tree();        
    }

    return 0;
}
