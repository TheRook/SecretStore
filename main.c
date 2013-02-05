#include <stdio.h>
#include <stdlib.h>
#include <db.h>

#include "base64.h"

#define KEY_SIZE 32

int
db_open(DB **store, const char* filename){
	int db_err;

	db_err = db_create(store, NULL, 0);
	if(db_err == 0){
		db_err = (**store).open(*store,
							 NULL,
							 filename,
							 NULL,
							 DB_BTREE,
							 DB_CREATE,
							 0);
	}
	return db_err;
}

char * get_nonce(int size){
	char * buf;
	char * ret;
	FILE * urand = fopen("/dev/urandom","r");
	buf = (char *)malloc(size);
	fgets(buf, size, urand);
	ret = base64_encode(buf, size);
	free(buf);
	close(urand);
	return ret;
}

char *
get_secret(DB *store, char* key){
	DBT lookup_key, secret;
	memset(&lookup_key, 0, sizeof(DBT));
	memset(&secret, 0, sizeof(DBT));

	lookup_key.data=key;
	lookup_key.size=strlen(key) + 1;

	store->get(store, NULL, &lookup_key, &secret, 0);

	return secret.data;
}

char *
new_secret(DB *store, int size){
	DBT key, secret;
	int db_err;

	memset(&key, 0, sizeof(DBT));
	memset(&secret, 0, sizeof(DBT));

	key.data = get_nonce(KEY_SIZE);
	key.size = strlen(key.data) + 1;

	secret.data = get_nonce(size);
	secret.size = strlen(secret.data) + 1;

	do{
		db_err = store->put(store, NULL, &key, &secret, DB_NOOVERWRITE);
		if(db_err == DB_KEYEXIST){
			//Birthday paradox, we may need a new key.
			free(key.data);
			key.data = get_nonce(KEY_SIZE);
		}
	}while(db_err == DB_KEYEXIST);

	free(secret.data);
	return key.data;
}

void
help(){
	printf("You need help son!\n");
}

int
main(int argc, char *argv[]){
	DB *store;
	char * key;
	int db_err;
	int key_size;

	db_err = db_open(&store, "store.db");
	if(db_err != 0){
		//error...
		return 1;
	}

	if(argc == 2){
		if(strlen(argv[1]) >= KEY_SIZE){
			key=get_secret(store, argv[1]);
			if(!key){
				printf("Not found.\n");
			}else{
				printf("%s\n", key);
			}
		}else{
			key_size = atoi(argv[1]);
			if(key_size > 0){
				key = new_secret(store, key_size);
				printf("%s\n", key);
				free(key);
			}else{
				help();
			}
		}
	}else{
		help();
	}

	if(store){
		store->close(store, 0);
	}
	return 0;
}



