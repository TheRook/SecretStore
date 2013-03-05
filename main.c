/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For fcntl */
#include <fcntl.h>

//#include <event2/event.h>
#include <event.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <glib-2.0/glib.h>

#include "store.h"

#include "main.h"

#define MAX_LINE 16384

void
proto_handler(struct bufferevent *request, short events, void* arg){
	struct evbuffer *bucket= bufferevent_get_input(request);
	struct evbuffer *output=bufferevent_get_output(request);

	leveldb_t* store=global_store;
	//int b64_size = base64_size(KEY_SIZE);
	char* response;
	char* message;
	size_t n_read_out;

	message=evbuffer_readln(bucket, &n_read_out, EVBUFFER_EOL_CRLF);
	if (n_read_out) {
		response=secret_handler(store, message);
		if(response){
			evbuffer_add_printf(output, "%s\r\n", response);
			free(response);
		}else{
			//todo error
		}

	} // otherwise ebuffer_readln() encountered an error.
	if(message) free(message);
}

char*
secret_handler(leveldb_t* store, char* req){
	char * resp=0;
	char * resp_b64=0;
	char * key_bin=0;
	size_t key_len;
	size_t secret_size;
	size_t value_len;

	printf("Got a request: '%s'\n", req);
	if(strlen(req) >= KEY_SIZE){
		key_bin = g_base64_decode(req, &key_len);
		resp = store_get(store, key_bin, key_len, &value_len);
		if(!resp){
			// todo how to indicate not found in protocol?
			printf("Not found.\n");
		} else {
			resp_b64=g_base64_encode(resp, value_len);
		}
	}else{
		secret_size = atoi(req);
		if(secret_size > 0){
			resp = new_secret(store, secret_size);
			resp_b64=g_base64_encode(resp, KEY_SIZE);
			printf("%s\n", resp_b64);
		}else{
			//todo error
			//help();
		}
	}

	return resp_b64;
}

//the return value is not null terminated.
char * get_nonce(int size){
	char * buf;
	FILE * urand = fopen("/dev/urandom","r");
	//not null-terminated,  so malloc the size,  not size+1!
	buf = (char *)malloc(size);
	fgets(buf, size, urand);

	fclose(urand);
	return buf;
}

char *
new_secret(leveldb_t *store, size_t size){
	char * secret = get_nonce(size);
	char * key = get_nonce(KEY_SIZE);

	store_put(store, key, KEY_SIZE, secret, size);

	free(secret);
	return key;
}

static void cleanup_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		perror("Error from bufferevent");
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
	}
}

void
do_accept(evutil_socket_t listener, short event, void *arg)
{
	struct accept_args* args=(struct accept_args*)arg;
    struct event_base *base = args->base;
    leveldb_t *store=args->store;
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
		bufferevent_setcb(bev, proto_handler, NULL, cleanup_cb, NULL);
		bufferevent_enable(bev, EV_READ|EV_WRITE);

    }
}

void
run(leveldb_t* store)
{
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base *base;
    struct event *listener_event;

    base = event_base_new();
    if (!base)
        return; /* TODO err*/

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(40713);

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

    struct accept_args *args=malloc(sizeof(struct accept_args)); // TODO free
    args->base=base;
    args->store=store;
    listener_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)args);
    /* TODO check it */
    event_add(listener_event, NULL);

    event_base_dispatch(base);
    free(args);
}

int
main(int c, char **v)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    leveldb_t* store;
    global_store=store=store_open("store.db");

    run(store);
    return 0;
}
