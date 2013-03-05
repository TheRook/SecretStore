#ifndef STORE_H
#define STORE_H

#include <leveldb/c.h>

leveldb_t * store_open(char * name);
char * store_get(leveldb_t * store, char * key,size_t key_size, size_t *read_len);
void store_put(leveldb_t * store, char * key, size_t key_size, char * value, size_t *value_len);
void store_delete(leveldb_t * store, char * key, size_t key_size);

#endif
