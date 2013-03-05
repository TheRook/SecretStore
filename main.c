//libglib2.0-dev

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

void do_read(evutil_socket_t fd, short events, void *arg);
void do_write(evutil_socket_t fd, short events, void *arg);


void
proto_handler(struct bufferevent *request, short events, void* arg){
	struct evbuffer *bucket= bufferevent_get_input(request);
	struct evbuffer *output=bufferevent_get_output(request);

	leveldb_t* store=global_store;

	int b64_size = base64_size(KEY_SIZE);
	char* response;
	char* message = (char*)malloc(b64_size + 1); // TODO who will free

	size_t n_read_out;
	do {
		message=evbuffer_readln(bucket, &n_read_out, EVBUFFER_EOL_CRLF);
		if (n_read_out) {
			response=secret_handler(store, message);
			if(response){
				evbuffer_add_printf(output, "%s\r\n", response);
				free(response);
			}else{
				//todo error
			}
		   free(message);
		} // otherwise ebuffer_readln() encountered an error.
	} while (message);
	//free(request); // TODO

}


char*
secret_handler(leveldb_t* store, char* req){
	char * resp=0;
	char * key_bin;
	char * value;
	size_t key_len;
	int key_size=0;
	size_t value_len;

	printf("Got a request: '%s'\n", req);
	if(strlen(req) >= KEY_SIZE){
		key_bin = g_base64_decode(req, &key_len);
		resp = store_get(store, key_bin, key_len, &value_len);

		if(!value){
			// todo error
			//printf("Not found.\n");
		}
	}else{
		key_size = atoi(req);
		if(key_size > 0){
			resp = new_secret(store, key_size);
			printf("%s\n", resp);
		}else{
			//todo error
			//help();
		}
	}

	return resp;
}

//the return value is not null terminated.
char * get_nonce(int size){
	char * buf;
	FILE * urand = fopen("/dev/urandom","r");
	//not null-terminated,  so malloc the size,  not size+1!
	buf = (char *)malloc(size);
	fgets(buf, size, urand);
	close(urand);
	return buf;
}

char *
new_secret(leveldb_t *store, int size){
	char *err = 0x00;
	char * secret = get_nonce(size);
	char * key = get_nonce(KEY_SIZE);

	store_put(store, key, KEY_SIZE, secret, size);

	/*leveldb_writeoptions_t *woptions  = leveldb_writeoptions_create();
	leveldb_put(store, woptions, key, strlen(key), secret, strlen(secret), &err);
	if(err){
		free(err);
		//todo error
	}*/
	free(secret);
	return key;
}



char
rot13_char(char c)
{
    /* We don't want to use isalpha here; setting the locale would change
     * which characters are considered alphabetical. */
    if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M'))
        return c + 13;
    else if ((c >= 'n' && c <= 'z') || (c >= 'N' && c <= 'Z'))
        return c - 13;
    else
        return c;
}

struct fd_state {
    char buffer[MAX_LINE];
    size_t buffer_used;

    size_t n_written;
    size_t write_upto;

    struct event *read_event;
    struct event *write_event;

    leveldb_t* store;
};

struct fd_state *
alloc_fd_state(leveldb_t* store, struct event_base *base, evutil_socket_t fd)
{
    struct fd_state *state = malloc(sizeof(struct fd_state));
    state->store=store;

    if (!state)
        return NULL;
    state->read_event = event_new(base, fd, EV_READ|EV_PERSIST, do_read, state);
    if (!state->read_event) {
        free(state);
        return NULL;
    }
    state->write_event =
        event_new(base, fd, EV_WRITE|EV_PERSIST, do_write, state);

    if (!state->write_event) {
        event_free(state->read_event);
        free(state);
        return NULL;
    }

    state->buffer_used = state->n_written = state->write_upto = 0;

    assert(state->write_event);
    return state;
}

void
free_fd_state(struct fd_state *state)
{
    event_free(state->read_event);
    event_free(state->write_event);
    free(state);
}

void
do_read(evutil_socket_t fd, short events, void *arg)
{
    struct fd_state *state = arg;
    char buf[1024];
    int i;
    ssize_t result;
    char* response;

    while (1) {
        assert(state->write_event);
        result = recv(fd, buf, sizeof(buf), 0);
        if (result <= 0)
            break;


        for (i=0; i < result; ++i)  {
            if (buf[i] == '\n') {
            	buf[i]=0x00;
            	response=secret_handler(state->store, buf); // TODO free
            	strncpy(state->buffer, response, strlen(response));

                assert(state->write_event);
                event_add(state->write_event, NULL);
                state->buffer_used=strlen(response);
                state->write_upto = state->buffer_used;
            }
        }
    }

    if (result == 0) {
        free_fd_state(state);
    } else if (result < 0) {
        if (errno == EAGAIN) // XXXX use evutil macro
            return;
        perror("recv");
        free_fd_state(state);
    }
}

void
do_write(evutil_socket_t fd, short events, void *arg)
{
    struct fd_state *state = arg;

    while (state->n_written < state->write_upto) {
        ssize_t result = send(fd, state->buffer + state->n_written,
                              state->write_upto - state->n_written, 0);
        if (result < 0) {
            if (errno == EAGAIN) // XXX use evutil macro
                return;
            free_fd_state(state);
            return;
        }
        assert(result != 0);

        state->n_written += result;
    }

    if (state->n_written == state->buffer_used)
        state->n_written = state->write_upto = state->buffer_used = 1;

    event_del(state->write_event);
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
    if (fd < 0) { // XXXX eagain??
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd); // XXX replace all closes with EVUTIL_CLOSESOCKET */
    } else {
    	evutil_make_socket_nonblocking(fd);
    	/* set up the bufferevent structure -- give the fisherman
				 a bin/bucket into which to put his fish */
		bev = bufferevent_socket_new(base, fd,
						BEV_OPT_CLOSE_ON_FREE);

		/* set-up the callbacks on that buffer: the read callback
			(in this case: buyfish) is executed when the client has
			sent data which is available to be 'read' (hence the name
			read callback) on the file descriptor -- in our analogy
			the fishmonger will buy fish when there is fish in
			bucket ready to be bought. */
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
        return; /*XXXerr*/

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(40713);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    evutil_make_socket_nonblocking(listener);

#ifndef WIN32
    {
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
#endif

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
    /*XXX check it */
    event_add(listener_event, NULL);

    event_base_dispatch(base);
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
