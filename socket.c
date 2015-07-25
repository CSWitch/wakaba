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

	int optval = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1)
		return 1;

	if(listen(server_fd, SERVER_BACKLOG) == -1)
		return 1;

	return 0;
}

int socket_nextclient()
{
	shutdown(client_fd, SHUT_RDWR);
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

size_t socket_read(int fd, char *buf, size_t len)
{
	char *bufp = buf;
	char packet[PACKET_SIZE];
	size_t packetsize = 0;

	while ((size_t) (bufp - buf) < len && (packetsize = read(fd, packet, PACKET_SIZE)) != 0){
		memcpy(bufp, packet, packetsize);
		bufp += packetsize;
	}

	return bufp - buf;
}

void socket_write(int fd, char *buf, ssize_t len)
{
	size_t packetsize = 0;

	while (len > 0){
		packetsize = MIN(len, PACKET_SIZE);
		if (send(fd, buf, packetsize, MSG_NOSIGNAL) == -1)
			break;
		buf += packetsize;
		len -= packetsize;
	}
}
