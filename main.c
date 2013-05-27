/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For fcntl */
#include <fcntl.h>
#include <event.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <glib-2.0/glib.h>

#include "store.h"
#include "error.h"
#include "config.h"
#include "main.h"


void
proto_handler(struct bufferevent *request, short events, void* arg){
	//struct accept_args* args=(struct accept_args*)arg; // TODO figure out arg
	leveldb_t* store=global_store;
	char buffer_test[1];
	struct evbuffer *bucket= bufferevent_get_input(request);
	struct evbuffer *output=bufferevent_get_output(request);
	char* response;
	char* message;
	size_t n_read_out;
	int is_error=0;
	size_t secret_size;
	char* secret_key;
	size_t key_len;

	message=evbuffer_readln(bucket, &n_read_out, EVBUFFER_EOL_CRLF);

	if (n_read_out) {
		//strcpy(buffer_test,message);
		//printf("Message: %s\n",message);
		// if the message is valid base64 and the message isn't a key,
		// and 1024 is the largest key.
		if(!is_valid_charset(message)){
			is_error=1;
			response=INVALID_REQUEST;
		}else if(n_read_out > 4){
			secret_key=g_base64_decode(message, &key_len);
			if(key_len == KEY_SIZE){
				response=get_secret(store, secret_key, key_len);
				if(!response){
					is_error=1;
					response=KEY_NOT_EXIST;
				}
			} else {
				is_error=1;
				response=INVALID_KEY_SIZE;
			}
		}else if(n_read_out > KEY_SIZE){
			is_error = 1;
		    response = REQUEST_TOO_LARGE;
		}else{
			secret_size=atoi(message);
			if(secret_size > 0 && secret_size <= MAX_SECRET_SIZE) {
				response=new_secret(store, secret_size);
			} else {
				is_error=1;
				response=INVALID_SECRET_SIZE;
			}
		}
	} else {
		// otherwise ebuffer_readln() encountered an error
		is_error=1;
		response=EMPTY_REQUEST;
	}

	if(message)
		free(message);

	evbuffer_add_printf(output, "%s\r\n", response);
	if(!is_error)//TODO:  is a free a free?  or do we need a g_free()?
		free(response);
}

int
is_valid_charset(char* str) {
	int i;
	for(i=0;i<strlen(str);i++){
		if( ! ((str[i] >= 'a' && str[i] <= 'z') ||
			   (str[i] >= 'A' && str[i] <= 'Z') ||
			   (str[i] >= '0' && str[i] <= '9') ||
			   str[i] == '/' || str[i] == '=' || str[i] == '+')) {
			return 0;
		}
	}
	return 1;
}

char*
get_secret(leveldb_t* store, char* key_bin, size_t key_len) {
	char* resp=0;
	char* resp_b64=0;
	size_t value_len;

	resp = store_get(store, key_bin, key_len, &value_len);
	if(resp){
		resp_b64=g_base64_encode(resp, value_len);
		free(resp);
	}
	g_free(key_bin);
	return resp_b64;
}

//the return value is null terminated.
char *
get_nonce(int size){
	char* buf;
	FILE* urand = fopen("/dev/urandom","r");
	buf = (char *)malloc(size + 1);
	fgets(buf, size + 1, urand);

	fclose(urand);
	return buf;
}

char *
new_secret(leveldb_t *store, size_t size){
	char* secret = get_nonce(size);
	char* key = get_nonce(KEY_SIZE);
	char* resp=0;

	//printf("new_secret(): key: %s\nsecret: %s\nsize: %d\n\n", key, secret, size);
	store_put(store, key, KEY_SIZE, secret, size);
	resp = g_base64_encode(key, KEY_SIZE);

	free(secret);
	free(key);

	return resp;
}

static void
cleanup_cb(struct bufferevent *bev, short events, void *ctx){
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
	}
}

void
do_accept(evutil_socket_t listener, short event, void *arg){
	struct accept_args* args=(struct accept_args*)arg;
    struct event_base* base = args->base;
    struct bufferevent* bev;

    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept(listener, (struct sockaddr*)&ss, &slen);
    if (fd < 0) { // TODO eagain??
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd); // TODO replace all closes with EVUTIL_CLOSESOCKET */
    } else {
    	evutil_make_socket_nonblocking(fd);
		bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

		/* set-up the callbacks on that buffer: the read callback
		 * (in this case: proto_handler) is executed when the client has
		 * sent data which is available to be read on the fd
		 */
		bufferevent_setcb(bev, proto_handler, NULL, cleanup_cb, NULL); // TODO arg?
		bufferevent_enable(bev, EV_READ|EV_WRITE);

    }
}

void
run(leveldb_t* store, int port){
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base* base;
    struct event* listener_event;

    base = event_base_new();
    if (!base) {
    	fprintf(stderr, "Cannot initialize libevent. Exiting");
    	return;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(port);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    evutil_make_socket_nonblocking(listener);

	int one = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return;
    }

    if (listen(listener, 16)<0) {
        perror("listen");
        return;
    }

    //args on the stack?
    struct accept_args *args=malloc(sizeof(struct accept_args));
    args->base=base;
    args->store=store;
    listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)args);
    event_add(listener_event, NULL);

    printf("Server started on port %d...\n", port);
    event_base_dispatch(base);
    free(args);
}

int
main(int c, char** v) {
	struct parsed_config config;
    leveldb_t* store;
    global_store=NULL;

	config = parse_config(CONFIG_FILE_PATH);
	if(!config.is_valid){
		fprintf(stderr, "Error occurred when reading config file %s, exiting.\n", CONFIG_FILE_PATH);
		return 1;
	}

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Opening database at %s...\n", config.db_path);
    global_store=store=store_open(config.db_path);

    run(store, config.port);
    //malloc'ed by parse_config(),  free it here:
    free_config_strings(&config);
    return 0;
}
