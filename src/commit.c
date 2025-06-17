#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "index.h"
#include "utils.h"

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
    for (size_t i = 0; i < entries->size; i++) {
        size_t toks_cnt = 0;
        char** toks = split_str(entries->list[i]->path, "/", &toks_cnt);
        assert(toks != NULL);
        if (toks && toks_cnt == depth) {

        } else if (toks && toks_cnt > depth) {
            char* key = join_str(toks, depth, "/");
            add_to_ll(&head, key, entries->list[i]);
            free(key);
        }
        free_str_arr(toks, toks_cnt);
    }

    ll_node_t *tmp = head;
    while (tmp != NULL) {
        write_tree_helper(tmp->entries, depth + 1);
        tmp = tmp->next;
    }

    free_ll(head);
    return NULL;
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

    return sha1_raw;
}
