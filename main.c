#include "sfh.h"

void cleanup()
{
	socket_terminate();
}

void terminate()
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
	sa.sa_handler = terminate;
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	int client_fd;
	struct request r;

	char err_invreq[] = "Invalid request\n";
	char err_toolarge[] = "File too large\n";
	char err_nodata[] = "No data received\n";

	while(1){
		client_fd = socket_nextclient();
		if (client_fd == -1)
			continue;

		printf("Got connection from %s\n", socket_clientaddr());

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
			continue;
		}

		if (r.type == R_POST)
			socket_write(client_fd, r.data, r.len);
		else if (r.type == R_GET)
			socket_puts(r.filename);

		if (r.data)
			free(r.data);
	}

	exit(0);
}
