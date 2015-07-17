#include "sfh.h"

void parse_request(int fd, struct request *r)
{
	char buf[512];
	size_t len = 0;
	char *filename = 0;
	char *length = 0;
	char *boundary = 0;

	len = read(fd, buf, 512);

	if (!len){
		r->type = R_INVALID;
		return;
	}

	if (strstr(buf, "POST") == buf)
		r->type = R_POST;
	else if (strstr(buf, "GET") == buf)
		r->type = R_GET;

	if (r->type == R_GET){
		filename = strchr(buf, '/');

		if (!filename || filename - buf > 6){
			r->type = R_INVALID;
			return;
		}

		len = MIN(strchr(filename, ' ') - filename, 127);
		strncpy(r->filename, filename, len);
		r->filename[len] = 0;
	}else if (r->type == R_POST){
		length = strstr(buf, "Content-Length: ");

		if (!length){
			r->type = R_INVALID;
			return;
		}

		length = strchr(length, ':') + 2;
		r->len = strtol(length, 0, 10);

		boundary = strstr(buf, "; boundary=");

		if (!boundary){
			r->type = R_INVALID;
			return;
		}

		boundary = strchr(boundary, '=') + 1;
		len = MIN(strchr(boundary, '\n') - 1 - boundary, 63);
		strncpy(r->boundary, boundary, len);
		r->boundary[len] = 0;
	}
}

void accept_request(int fd, struct request *r)
{
	char *buf = malloc(r->len);
	size_t len = 0;

	len = read(fd, buf, r->len);

	//Parse form.

	fwrite(buf, 1, len, stdout);
	free(buf);
}

int main()
{
	if (socket_initialize()){
		puts("Failed to initialize server");
		return 1;
	}

	int client_fd;
	struct request r;

	char err_invreq[] = "Invalid request\n";
	char err_toolarge[] = "File too large\n";

	while(1){
		client_fd = socket_nextclient();
		if (client_fd == -1)
			continue;

		printf("Got connection from %s\n", socket_clientaddr());

		memset(&r, 0, sizeof(r));
		parse_request(client_fd, &r);

		if (r.type == R_INVALID){
			socket_puts(err_invreq);
			continue;
		}

		if (r.len > 8192){
			socket_puts(err_toolarge);
			continue;
		}
		if (r.type == R_POST)
			accept_request(client_fd, &r);
		if (r.type == R_INVALID){
			socket_puts(err_invreq);
			continue;
		}
	}

	socket_close();
	return 0;
}
