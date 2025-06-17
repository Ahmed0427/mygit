#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "index.h"
#include "objects.h"
#include "utils.h"

#define DIR_MODE 16384

typedef struct {
    idx_entry_t** list;
    size_t size;
} entries_t;

typedef struct ll_node_t {
    char* key;
    entries_t* entries;
    struct ll_node_t* next;
} ll_node_t;

void free_ll(ll_node_t* head) {
    ll_node_t* tmp = head;
    while(tmp) {
        ll_node_t* next = tmp->next;
        free(tmp->key);
        free_entries(tmp->entries->list, tmp->entries->size);
        free(tmp->entries);
        free(tmp);
        tmp = next;
    }
}

int add_to_ll(ll_node_t** head, char* key, idx_entry_t *ent) {
    assert(key != NULL);
    assert(ent != NULL);
    ll_node_t* tmp = *head;
    while(tmp) {
        if (strcmp(key, tmp->key) == 0) {
            tmp->entries->list = realloc(tmp->entries->list,
                         (tmp->entries->size + 1) * sizeof(idx_entry_t*));
            tmp->entries->list[tmp->entries->size++] = copy_entry(ent);
            return 0;
        }
        tmp = tmp->next;
    }

    ll_node_t *new_node = malloc(sizeof(ll_node_t));
    new_node->entries = malloc(sizeof(entries_t));
    new_node->entries->list = malloc(sizeof(idx_entry_t*));
    new_node->entries->list[0] = copy_entry(ent); 
    new_node->entries->size = 1;
    new_node->key = strdup(key);

    new_node->next = *head;
    *head = new_node;


    return 0;
}

char* write_tree_helper(entries_t* entries, size_t depth) {
    ll_node_t *head = NULL;
    size_t tree_obj_size = 0;
    size_t tree_obj_cap = 512;
    unsigned char *tree_obj_data = malloc(tree_obj_cap);
    for (size_t i = 0; i < entries->size; i++) {
        idx_entry_t *ent = entries->list[i];

        size_t toks_cnt = 0;
        char** toks = split_str(ent->path, "/", &toks_cnt);
        for (size_t j = 0; j < toks_cnt; j++) {
            assert(toks[j] != NULL);
        }
        assert(toks != NULL);

        if (toks && toks_cnt == depth) {
            // 6 for mode in octal
            // 1 for space
            // 1 for \0 separator
            // 20 for the raw sha1
            // entry format: [mode] [file/dir name]\0[SHA-1 of blob or tree]
            
            size_t name_len = strlen(toks[depth - 1]);
            size_t ent_size = 6 + 1 + name_len + 1 + 20;
            char* tree_ent = calloc(ent_size, 1); 
            int written = sprintf(tree_ent, "%06o %s", ent->mode, toks[depth - 1]);
            memcpy(tree_ent + written + 1, ent->sha1, 20);

            if (tree_obj_size + ent_size >= tree_obj_cap) {
                tree_obj_cap *= 2;
                tree_obj_data = realloc(tree_obj_data, tree_obj_cap);
                assert(tree_obj_data != NULL);
            }
            memcpy(tree_obj_data + tree_obj_size, tree_ent, ent_size);
            tree_obj_size += ent_size;
            free(tree_ent);

        } else if (toks && toks_cnt > depth) {
            char* key = join_str(toks, depth, "/");
            add_to_ll(&head, key, entries->list[i]);
            free(key);
        }
        free_str_arr(toks, toks_cnt);
    }

    ll_node_t *tmp = head;
    while (tmp != NULL) {
        size_t toks_cnt = 0;
        char** toks = split_str(tmp->key, "/", &toks_cnt);
        for (size_t j = 0; j < toks_cnt; j++) {
            assert(toks[j] != NULL);
        }
        assert(toks != NULL);

        char* tree_sha1 = write_tree_helper(tmp->entries, depth + 1);
        size_t name_len = strlen(toks[depth - 1]);
        size_t ent_size = 6 + 1 + name_len + 1 + 20;
        char* tree_ent = calloc(ent_size, 1); 
        int written = sprintf(tree_ent, "%06o %s", DIR_MODE, toks[depth - 1]);
        memcpy(tree_ent + written + 1, tree_sha1, 20);

        if (tree_obj_size + ent_size >= tree_obj_cap) {
            tree_obj_cap *= 2;
            tree_obj_data = realloc(tree_obj_data, tree_obj_cap);
            assert(tree_obj_data != NULL);
        }
        free(tree_sha1);
        memcpy(tree_obj_data + tree_obj_size, tree_ent, ent_size);
        tree_obj_size += ent_size;
        free_str_arr(toks, toks_cnt);
        tmp = tmp->next;
        free(tree_ent);
    }

    free_ll(head);
    char* res_sha1 = (char*)hash_obj(tree_obj_data, tree_obj_size, "tree", true);
    free(tree_obj_data);
    return res_sha1;
}


char *write_tree() {
    idx_t *idx = read_idx();     
    entries_t* entries = malloc(sizeof(entries_t));
    entries->list = calloc(idx->hdr->cnt, sizeof(idx_entry_t*));
    entries->size = idx->hdr->cnt;

    for (size_t i = 0; i < entries->size; i++) {
        entries->list[i] = copy_entry(idx->entries[i]);
    }

    char* sha1_raw = write_tree_helper(entries, 1);

    free_entries(entries->list, entries->size);
    free(entries);
    free_idx(idx);

    if (sha1_raw != NULL) {
        print_sha1((uint8_t*)sha1_raw);
    }
    free(sha1_raw);

    return NULL;
}
