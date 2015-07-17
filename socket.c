#include "sfh.h"

int server_fd;
int client_fd;

struct sockaddr_in server_addr;
struct sockaddr_in client_addr;

socklen_t client_len;

char str_client_addr[16];

int socket_initialize()
{
	memset(&server_addr, 0, sizeof(server_addr));
	client_len = sizeof(client_len);

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(SERVER_PORT);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
		return 1;

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1)
		return 1;

	if(listen(server_fd, SERVER_BACKLOG) == -1)
		return 1;

	return 0;
}

int socket_nextclient()
{
	close(client_fd);

	client_fd = accept(server_fd, (struct sockaddr *)  &client_addr, &client_len);

	return client_fd;
}

void socket_terminate()
{
	close(client_fd);
	close(server_fd);
}

char *socket_clientaddr()
{
	uint32_t addr = client_addr.sin_addr.s_addr;

	memset(str_client_addr, 0, 16);
	inet_ntop(AF_INET, &addr, str_client_addr, 16);

	return str_client_addr;
}

void socket_puts(char *str)
{
	write(client_fd, str, strlen(str));
}
