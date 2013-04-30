/*
 * Simplify leveldb access and error reporting.
 */

#include <leveldb/c.h>
#include "store.h"
#include <stdio.h>

leveldb_t*
store_open(char * name){
	leveldb_t *db = 0x00;
    leveldb_options_t *options;
    leveldb_readoptions_t *roptions;
    leveldb_writeoptions_t *woptions;
    char *err = 0x00;
	options = leveldb_options_create();
    leveldb_options_set_create_if_missing(options, 1);
    db = leveldb_open(options, name, &err);

    if (err) {
		fprintf(stderr, "error: %s\n", err);
		free(err);
		db = 0x00;
    }
    return db;
}

char*
store_get(leveldb_t * store, char * key,size_t key_size, size_t *read_len){
	char * err=0x00;
	leveldb_readoptions_t *read_options=leveldb_readoptions_create();
	char * resp = leveldb_get(store,read_options, key, key_size, read_len, &err);
	leveldb_readoptions_destroy(read_options);
	if(err){
		fprintf(stderr, "error: %s\n", err);
		free(err);
	}
	return resp;
}

void
store_put(leveldb_t * store, char * key, size_t key_size, char * value, size_t value_len){
	char * err=0x00;
	leveldb_writeoptions_t *write_options=leveldb_writeoptions_create();
	//char * resp = leveldb_put(store,  leveldb_readoptions_create(), key, key_size, &read_len, &err);
	leveldb_put(store,write_options , key, key_size, value, value_len, &err);
	leveldb_writeoptions_destroy(write_options);
	if(err){
		fprintf(stderr, "error: %s\n", err);
		free(err);
	}
}

void
store_delete(leveldb_t * store, char * key, size_t key_size){
	char * err=0x00;
	leveldb_writeoptions_t *write_options=leveldb_writeoptions_create();
	leveldb_delete(store, write_options, key, key_size, &err);
	leveldb_writeoptions_destroy(write_options);
	if(err){
		fprintf(stderr, "error: %s\n", err);
		free(err);
	}
}
