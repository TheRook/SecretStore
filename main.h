/*
 * main.h
 *
 *  Created on: Feb 22, 2013
 *      Author: grey
 */

#ifndef MAIN_H_
#define MAIN_H_

char *
get_secret(DB *store, char* key);
char *
new_secret(DB *store, int size);

#endif /* MAIN_H_ */
