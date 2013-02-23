#include <stdio.h>
#include <stdlib.h>
#include <db.h>
#include "base64.h"

//start_deamon
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <sys/queue.h>
#include "main.h"

#define KEY_SIZE 32
#define TIMEOUT 200
#define DB_PATH "store.db"
#define THREAD_POOL_MIN 5
#define THREAD_POOL_MAX 100

int
db_open(DB **store, const char* filename){
	int db_err;

	//DB_CREATE - Create a new DB if one doesn't exist.
	//DB_INIT_CDB - create a a non-deadlocking multi-reader single writer access.
	//DB_INIT_MPOOl - init a shared memory buffer pool sub-system.
	//docs - http://docs.oracle.com/cd/E17076_02/html/programmer_reference/cam.html
	u_int32_t flags = DB_CREATE;//| DB_INIT_CDB | DB_INIT_MPOOL;

	db_err = db_create(store, NULL, 0);
	if(db_err == 0){
		db_err = (**store).open(*store,
							 NULL,
							 filename,
							 NULL,
							 DB_BTREE,
							 flags,
							 0);
	}
	return db_err;
}

struct thread_args{
	int sock;
	DB* store;
	int permanent; // bool
	pthread_mutex_t thread_tracker;
	int *thread_count;
	//apr_queue_t *work_queue;
};

char*
request_handler(DB* store, char* req){
	char * key=0;
	int key_size=0;

	printf("Got a request: '%s'\n", req);
	if(strlen(req) >= KEY_SIZE){
		key=get_secret(store, req);
		if(!key){
			// todo error
			//printf("Not found.\n");
		}
	}else{
		key_size = atoi(req);
		if(key_size > 0){
			key = new_secret(store, key_size);
			printf("%s\n", key);
		}else{
			//todo error
			//help();
		}
	}

	return key;
}

void
proto_handler(DB* store, int sock, int timeout){
	int b64_size = base64_size(KEY_SIZE);
	char* response;
	char* request = (char*)malloc(b64_size + 1); // TODO who will free

	int n;
	char c;
	int read_idx=0;
	int connection_active=1;

	printf("About to read\n");
	while(connection_active) {
		read_idx=0;
		while(1) {
			n = recv(sock, &c, 1, MSG_WAITALL);
			if(n == 0 || n == -1) { // either an orderly shutdown or error occurred
				connection_active=0;
				break; // the client has disconnected
			}

			if(read_idx >=b64_size){
				// out of bounds, TODO error
				break;
			}

			if(c == '\n'){
				if(request[read_idx-1]=='\r'){
					request[read_idx-1]=0x00;
				}else{
					request[read_idx]=0x00;
				}
				break;
			}
			request[read_idx]=c;
			read_idx++;
		}
		if(connection_active){
			printf("%s\n", request);

			response=request_handler(store, request);
			if(response){
				write(sock, response, strlen(response));
				write(sock, "\r\n", 2);
				free(response);
				//bzero(request,b64_size);
			}else{
				//todo error
			}
		}
	}

    free(request);
}

int
start_connection(pthread_mutex_t thread_tracker, int * thread_count){
	pthread_mutex_lock(&thread_tracker);
	thread_count++;
	pthread_mutex_unlock(&thread_tracker);
}

void
end_connection(pthread_mutex_t thread_tracker, int * thread_count){
	pthread_mutex_lock(&thread_tracker);
	thread_count--;
	pthread_mutex_unlock(&thread_tracker);
}

void* thread_entry_point(void *thread_args){
	int sock= ((struct thread_args*)thread_args)->sock;
	DB* store=((struct thread_args*)thread_args)->store;
	int permanent=((struct thread_args*)thread_args)->permanent;
	pthread_mutex_t thread_tracker=((struct thread_args*)thread_args)->thread_tracker;
	int* thread_count=((struct thread_args*)thread_args)->thread_count;
	start_connection(thread_tracker,thread_count);
	//proto_handler blocks until the client leaves or we hit a timeout.
	proto_handler(store, sock, 30);
	end_connection(thread_tracker,thread_count);
}

struct conn_thread {
    int conn;
    LIST_ENTRY(conn_thread) pointers;
};
LIST_HEAD(conn_list, conn_thread);

//
int
start_daemon(DB *store, int port, int thread_pool_min, int thread_pool_max){
	int sock, conn;
	struct sockaddr_in my_addr;
	int optval = 1;
	struct sockaddr client;
	int client_size;
    LIST_HEAD(conn_list, conn_thread) head;
    LIST_INIT(&head);

	pthread_mutex_t thread_tracker;
	int thread_count = thread_pool_min;


	//thread_count is a thread-safe counter,  and is not used for blocking.
	pthread_mutex_init(&thread_tracker, NULL);

	pthread_t* threads;
	struct thread_args args;

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	sock = socket( PF_INET, SOCK_STREAM, 0 );
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval) );
	bind( sock, (struct sockaddr* )&my_addr, sizeof( struct sockaddr_in ) );

	//10 BACK LOG'ed requests.
	listen(sock, 10);

	// create prefetch threads which will accept(sock)
	args.store=store;
	args.sock=sock;
	args.permanent=1;
	args.thread_tracker = thread_tracker;
	args.thread_count = &thread_count;
	//args.work_queue = &work_queue;

	threads = malloc(sizeof(pthread_t) * thread_pool_max);
	if(!threads){
		return 1;
	}

	int i;
	for(i=0;i<thread_pool_min;i++){
		pthread_create(&threads[i], NULL, thread_entry_point, (void*)&args);
	}

	while(1){
		conn = accept( sock, (struct sockaddr *)&client, &client_size );
	    //we may not need to use malloc...
	    struct conn_thread *item = malloc(sizeof(struct conn_thread));
	    item->conn = conn;
	    LIST_INSERT_HEAD(&head, item, pointers);
	}
	return 0;
}

char * get_nonce(int size){
	char * buf;
	char * ret;
	FILE * urand = fopen("/dev/urandom","r");
	//not null-terminated,  so malloc the size,  not size+1!
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
	int error;
	char * ret = 0;
	memset(&lookup_key, 0, sizeof(DBT));
	memset(&secret, 0, sizeof(DBT));

	lookup_key.data=key;
	lookup_key.size=strlen(key) + 1;

	error = store->get(store, NULL, &lookup_key, &secret, 0);

	if(error != DB_NOTFOUND){
		ret = (char *) malloc(secret.size+1);
		memcpy(ret, secret.data, secret.size);
	}
	return ret;
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
	int db_err;
	int key_size;

	db_err = db_open(&store, DB_PATH);
	if(db_err != 0){
		printf("Error opening database at '%s'\n", DB_PATH);

		switch(db_err){
		case DB_LOCK_DEADLOCK:
			printf("DB_LOCK_DEADLOCK\n");
			break;
		case DB_LOCK_NOTGRANTED:
			printf("DB_LOCK_NOTGRANTED\n");
			break;
		case ENOENT:
			printf("ENOENT\n");
			break;
		case DB_OLD_VERSION:
			printf("DB_OLD_VERSION\n");
			break;
		case EEXIST:
			printf("EEXIST\n");
			break;
		case EINVAL:
			printf("EINVAL\n");
			break;
		case DB_REP_HANDLE_DEAD:
			printf("DB_REP_HANDLE_DEAD\n");
			break;
		}
		//error...
		return 1;
	}

	start_daemon(store, 50100, 5, 100);

	/* TODO: move to handle_request()
	if(argc == 2){
		request_hanlder(argv[1]);
	}else{
		help();
	}*/

	if(store){
		store->close(store, 0);
	}
	return 0;
}



