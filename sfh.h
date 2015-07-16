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

int socket_initialize();

int socket_nextclient();

int socket_nextclient();

void socket_close();

char *socket_clientaddr();

#endif
