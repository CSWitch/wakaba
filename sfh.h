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

#define SERVER_PORT 8080
#define SERVER_BACKLOG 5
#define PACKET_SIZE 2048
#define FILE_SIZE_LIMIT 60000000 //60 MB
#define DOMAIN_NAME "wakaba.dhcp.io"

#define MIN(X, Y) (X < Y ? X : Y)

enum request_type{
	R_INVALID,
	R_POST,
	R_GET,
	R_CACHED
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

struct file_entry{
	char *data;
	size_t len;
	unsigned long long id;
};

int socket_initialize();

int socket_nextclient();

void socket_terminate();

char *socket_clientaddr();

void socket_puts(char *str);

size_t socket_read(int fd, char *buf, size_t len);

void socket_write(int fd, char *buf, ssize_t len);

void http_process_request(int fd, struct request *r);

unsigned long long database_push(char *data, size_t len);

struct file_entry *database_getfile(char *name);

void database_terminate();

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
			return haystack + h_pos;
		}
	}

	return 0;
}

#endif
