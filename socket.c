#include "sfh.h"

int server_fd;
struct sockaddr_in server_addr;

int client_fd;
struct sockaddr_in client_addr;
socklen_t client_len = sizeof(struct sockaddr_in);

int socket_initialize()
{
	memset(&server_addr, 0, sizeof(server_addr));

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

void socket_clientaddr(struct client_ctx *cc)
{
	uint32_t addr = client_addr.sin_addr.s_addr;

	memset(cc->str_addr, 0, 16);
	inet_ntop(AF_INET, &addr, cc->str_addr, 16);
}

struct client_ctx *socket_nextclient()
{
	struct client_ctx *cc;

	client_fd = accept(server_fd, (struct sockaddr *)  &client_addr, &client_len);
	if (client_fd == -1)
		return 0;

	cc = calloc(sizeof(*cc), 1);
	cc->fd = client_fd;
	socket_clientaddr(cc);

	return cc;
}

void socket_terminate()
{
	close(server_fd);
}

void socket_puts(int fd, char *str)
{
	write(fd, str, strlen(str));
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
