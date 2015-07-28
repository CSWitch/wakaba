#include "sfh.h"

void *process_request(void *p)
{
	char *err_invreq = "Invalid request\n";
	char *err_toolarge = "File too large\n";
	char *err_nodata = "No data received\n";
	char *err_notfound = "File not found in database\n";

	struct client_ctx *cc = p;
	int client_fd = cc->fd;
	struct request r;

	memset(&r, 0, sizeof(r));
	http_process_request(client_fd, &r);

	if (r.type == R_INVALID){
		switch(errno){
			case EFBIG:
				socket_puts(client_fd, err_toolarge);
				break;
			case ENODATA:
				socket_puts(client_fd, err_nodata);
				break;
			case EINVAL:
			default:
				socket_puts(client_fd, err_invreq);
				break;
		}
		errno = 0;
		goto RET;
	}

	if (r.type == R_POST){
		unsigned long long id = database_push(r.data, r.len);
		char buf[128];

		printf("%s uploaded file of %zu bytes (%llx)\n", cc->str_addr, r.len, id);

		snprintf(buf, 128, "http://%s:%i/%llx\n", config->domainname, config->port, id);
		socket_puts(client_fd, buf);
	}else if (r.type == R_GET){
		char *data = 0;
		size_t len = database_getfile(r.filename, &data);
		char http_header[2048];

		if (!data){
			socket_puts(client_fd, err_notfound);
			goto RET;
		}

		printf("%s requested file %s\n", cc->str_addr, r.filename);

		snprintf(http_header, 2048, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\nExpires: Sun, 17-jan-2038 19:14:07 GMT\r\n\r\n", len);
		socket_puts(client_fd, http_header);
		socket_write(client_fd, data, len);
	}else if (r.type == R_CACHED){
		char *http_header = "HTTP/1.0 304 Not Modified\r\n\r\n";

		if (!database_getfile(r.filename, 0)){
			socket_puts(client_fd, err_notfound);
			goto RET;
		}

		socket_puts(client_fd, http_header);
	}

RET:
	shutdown(client_fd, SHUT_RDWR);
	close(client_fd);
	cc->ts->terminated = 1;
	free(cc);
	pthread_exit(0);
}
