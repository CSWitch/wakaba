#include "sfh.h"

void cleanup()
{
	socket_terminate();
	database_terminate();
}

void sigterm()
{
	puts("Exiting gracefully");
	exit(0);
}

int main()
{
	if (socket_initialize()){
		puts("Failed to initialize server");
		return 1;
	}
	atexit(cleanup);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm;
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	int client_fd;
	struct request r;

	char *err_invreq = "Invalid request\n";
	char *err_toolarge = "File too large\n";
	char *err_nodata = "No data received\n";
	char *err_notfound = "File not found in database\n";

	while(1){
		client_fd = socket_nextclient();
		if (client_fd == -1)
			continue;

		memset(&r, 0, sizeof(r));
		http_process_request(client_fd, &r);

		if (r.type == R_INVALID){
			switch(errno){
				case EFBIG:
					socket_puts(err_toolarge);
					break;
				case ENODATA:
					socket_puts(err_nodata);
					break;
				case EINVAL:
				default:
					socket_puts(err_invreq);
					break;
			}
			errno = 0;
			continue;
		}

		if (r.type == R_POST){
			unsigned long long id = database_push(r.data, r.len);
			char buf[128];

			printf("%s uploaded file of %zu bytes (%llx)\n", socket_clientaddr(), r.len, id);

			snprintf(buf, 128, "http://" DOMAIN_NAME "/%llx\n", id);
			socket_puts(buf);
		}else if (r.type == R_GET){
			struct file_entry *fe = database_getfile(r.filename);
			char http_header[2048];

			if (!fe){
				socket_puts(err_notfound);
				continue;
			}

			printf("%s requested file %s\n", socket_clientaddr(), r.filename);

			snprintf(http_header, 2048, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\nExpires: Sun, 17-jan-2038 19:14:07 GMT\r\n\r\n", fe->len);
			socket_puts(http_header);
			socket_write(client_fd, fe->data, fe->len);
		}else if (r.type == R_CACHED){
			char *http_header = "HTTP/1.0 304 Not Modified\r\n\r\n";

			if (!database_getfile(r.filename)){
				socket_puts(err_notfound);
				continue;
			}

			socket_puts(http_header);
			printf("%s requested cached file\n", socket_clientaddr());
		}
	}

	exit(0);
}
