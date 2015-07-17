#ifndef SFH_H
#define SFH_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080
#define SERVER_BACKLOG 5

#define MIN(X, Y) (X < Y ? X : Y)

enum request_type{
	R_INVALID,
	R_POST,
	R_GET
};

struct request{
	enum request_type type;
	char filename[128];
	size_t len;
	char boundary[64];
	char *data;
};

int socket_initialize();

int socket_nextclient();

int socket_nextclient();

void socket_close();

char *socket_clientaddr();

void socket_puts(char *str);

#endif
