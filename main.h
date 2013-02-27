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

char *
get_secret(leveldb_t *store, char* key);
char *
new_secret(leveldb_t *store, int size);

#endif /* MAIN_H_ */
