#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "utils.h"
#include "index.h"
#include "status.h"
#include "commit.h"
#include "objects.h"

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
    printf("mygit commands:\n");
    printf("  init                                        Init repo\n");
    printf("  cat-file <sha1>                             Prints the content of the repo obj\n");
    printf("  add <paths...>                              Add files/dirs to index\n");
    printf("  cat-file <obj-hash>                         Print content for repo obj\n");
    printf("  ls-files [-s]                               List index files (-s = detailed)\n");
    printf("  status                                      Show the working tree status\n");
    printf("  commit -m MESSAGE --author=\"NAME <EMAIL>\"   Commit with message and author\n");
    printf("  help                                        Show this message\n");
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
                free_str_arr(paths, cnt);
            } else if (file_exists(argv[i])) {
                char* paths[] = {argv[i]}; 
                add_to_index(paths, 1);
            } else {
                fprintf(stderr, "ERROR: file '%s' doesn't exit\n", argv[i]);
            }
        }
    } else if (strcmp(argv[1], "cat-file") == 0) {
        if (argc > 3) {
            fprintf(stderr, "ERROR: too many args\n");
            exit(1);
        } else if (argc == 3) {
            cat_file(argv[2]);
        } else {
            fprintf(stderr, "Usage: cat-file <obj-hash>\n");
            exit(1);
        }
    } else if (strcmp(argv[1], "commit") == 0) {
        char *author = NULL;
        char *message = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
                message = argv[++i];
            } else if (strncmp(argv[i], "--author=", 9) == 0) {
                author = argv[i] + 9;
            }
        }

        if (!message || !author) {
            fprintf(stderr, "Usage: mygit commit -m MESSAGE --author=\"NAME <EMAIL>\"\n");
            exit(1);
        }

        int reti;
        regex_t regex;
        reti = regcomp(&regex, "^[^\"]* <[^@<>]+@[^@<>]+\\.[^@<>]+>$", REG_EXTENDED);
        if (reti) {
            fprintf(stderr, "Could not compile regex\n");
            exit(1);
        }
        reti = regexec(&regex, author, 0, NULL, 0);
        if (reti) {
            fprintf(stderr, "Invalid author format. Expected: \"NAME <EMAIL>\"\n");
            exit(1);
        }
        regfree(&regex);

        commit(author, message);        
    }
    return 0;
}
