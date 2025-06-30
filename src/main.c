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
    printf("  add <file>...                               Add files/dirs to index\n");
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
        int fcnt = 0;
        char** paths = NULL;
        collect_files(".", &paths, &fcnt);

        for (int i = 2; i < argc; i++) {
            idx_t* idx = read_idx();
            if (!idx) { continue; }

            int mod_size = 0, new_size = 0, del_size = 0; 
            char** mod_list = get_modified_files(paths, fcnt, idx, &mod_size);
            char** new_list = get_new_files(paths, fcnt, idx, &new_size);
            char** del_list = get_deleted_files(paths, fcnt, idx, &del_size);

            if (strcmp(argv[i], ".") == 0) {
                add_to_index(mod_list, mod_size);
                add_to_index(new_list, new_size);
                remove_from_index(del_list, del_size);
                break;
            } else if (file_exists(argv[i])) {
                bool found = false;
                for (int j = 0; j < new_size; j++) {
                    if (strncmp(new_list[j], argv[i], 256) == 0) {
                        found = true; 
                        break;
                    }
                }
                for (int j = 0; j < mod_size; j++) {
                    if (strncmp(mod_list[j], argv[i], 256) == 0) {
                        found = true; 
                        break;
                    }
                }

                if (!found) {
                    fprintf(stderr, "ERROR: file '%s' doesn't exit\n", argv[i]);
                } else {
                    char* path[] = {argv[i]}; 
                    add_to_index(path, 1);
                }
            } else {
                bool found = false;
                for (int j = 0; j < del_size; j++) {
                    if (strncmp(del_list[j], argv[i], 256) == 0) {
                        found = true; 
                        break;
                    }
                }

                if (!found) {
                    fprintf(stderr, "ERROR: file '%s' doesn't exit\n", argv[i]);
                } else {
                    char* path[] = {argv[i]}; 
                    remove_from_index(path, 1);
                }
            }
            free_str_arr(new_list, new_size);
            free_str_arr(mod_list, mod_size);
            free_str_arr(del_list, del_size);
        }
        free_str_arr(paths, fcnt);

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
    } else {
        fprintf(stderr, "'%s' is not a mygit command. See 'mygit help'\n", argv[1]);
    }
    return 0;
}
