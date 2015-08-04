#ifndef SFH_H
#define SFH_H

#define _POSIX_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <pwd.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/statvfs.h>
#include <time.h>
#include <sys/prctl.h>

#define SERVER_BACKLOG 1
#define PACKET_SIZE 8192
#define DATA_DIR "/var/lib/wakaba/"
#define CONF_DIR "/etc/wakaba/"

#define MIN(X, Y) (X < Y ? X : Y)

struct config{
	uint16_t port_http;
	uint16_t port_https;
	size_t max_file_size;
	size_t max_cache_size;
	char domainname[128];
	char username[128];
	char db_persist;
	char browser_cache;
	char ssl_cert[128];
	char ssl_pkey[128];
	char admin_pwd[128];
};

struct config *config;

enum request_type{
	R_INVALID,
	R_POST,
	R_GET,
	R_CACHED,
	R_CMD
};

struct request{
	enum request_type type;
	char filename[128];
	size_t len;
	char *data;
};

struct lnode{
	void *data;
	struct lnode *next;
	struct lnode *prev;
};

struct thread_state{
	pthread_t thread;
	char terminated;
};

struct client_ctx{
	int fd;
	char str_addr[16];
	struct thread_state *ts;
	SSL *ssl;
	struct request *r;
};

struct cache_entry{
	char *data;
	size_t len;
	unsigned long long id;
};

struct db_stats{
	size_t disk_max;
	size_t disk_use;
	size_t cache_max;
	size_t cache_use;
	size_t files;
	size_t cache_entries;
};

int socket_initialize();

void socket_close(struct client_ctx *cc);

struct client_ctx *socket_nextclient();

void socket_terminate();

void socket_puts(struct client_ctx *cc, char *str);

size_t socket_read(struct client_ctx *cc, char *buf, size_t len);

void socket_write(struct client_ctx *cc, char *buf, ssize_t len);

size_t socket_gets(struct client_ctx *cc, char *buf, size_t len);

void http_process_request(struct client_ctx *cc, struct request *r);

unsigned long long database_push(char *data, size_t len);

size_t database_getfile(char *name, char **datap);

void database_terminate();

int database_init();

int database_flush();

int database_getstats(struct db_stats *stats);

int database_rm(char *name);

void cache_push(char *data, size_t len, unsigned long long id);

struct cache_entry *cache_get(unsigned long long id);

void cache_terminate();

void cache_prune();

void cache_getstats(struct db_stats *stats);

int cache_rm(unsigned long long id);

void *process_request(void *p);

static inline struct lnode *lnode_push(struct lnode *head, struct lnode *node)
{
	if (head){
		node->next = head;
		node->prev = head->prev;

		if (head->prev)
			head->prev->next = node;

		head->prev = node;
	}

	return node;
}

static inline struct lnode *lnode_pop(struct lnode *head)
{
	if (head->prev)
		head->prev->next = head->next;
	if (head->next)
		head->next->prev = head->prev;

	return head;
}

static inline struct lnode *listend(struct lnode *head)
{
	struct lnode *cur = head;

	while(cur && cur->next)
		cur = cur->next;

	return cur;
}

static inline void *memmem(void *haystack, size_t haystack_len, void *needle, size_t needle_len)
{
	size_t match;

	for (size_t h_pos = 0; h_pos < haystack_len; h_pos++){
		match = 0;
		for (size_t n_pos = 0; n_pos < needle_len; n_pos++){
			if ((uint8_t) ((uint8_t *) haystack)[h_pos + n_pos] == (uint8_t) ((uint8_t *) needle)[n_pos]){
				match++;
			}
		}
		if (match >= needle_len){
			return (uint8_t *) haystack + h_pos;
		}
	}

	return 0;
}

#endif
