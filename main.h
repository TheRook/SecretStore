/*
 * main.h
 *
 *  Created on: Feb 22, 2013
 *      Author: grey
 */

#ifndef MAIN_H_
#define MAIN_H_

#include <leveldb/c.h>

#define KEY_SIZE 32
#define TIMEOUT 200
#define DB_PATH "store.db"
#define THREAD_POOL_MIN 5
#define THREAD_POOL_MAX 100
#define MAX_LINE 100
#define MAX_SECRET_SIZE 1024
#define CONFIG_FILE_PATH "secretstore.conf"

char*
get_secret(leveldb_t* store, char* key_bin, size_t key_len);
char *
new_secret(leveldb_t *store, size_t size);
char*
secret_handler(leveldb_t* store, char* req);

struct accept_args {
	struct event_base *base;
	leveldb_t *store;
};


#endif /* MAIN_H_ */
