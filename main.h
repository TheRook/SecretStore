/*
 * main.h
 *
 *  Created on: Feb 22, 2013
 *      Author: grey
 */

#ifndef MAIN_H_
#define MAIN_H_

char *
get_secret(leveldb_t *store, char* key);
char *
new_secret(leveldb_t *store, int size);

#endif /* MAIN_H_ */
