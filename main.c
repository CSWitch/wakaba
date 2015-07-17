#include "sfh.h"

//TODO: Catch SIGTERM.

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
		http_process_request(client_fd, &r);

		if (r.type == R_INVALID){
			socket_puts(err_invreq);
			continue;
		}

		if (r.len > 8192){
			socket_puts(err_toolarge);
			continue;
		}

		if (r.type == R_POST)
			socket_write(client_fd, r.data, r.len);
		else if (r.type == R_GET)
			socket_puts("Yes, i see you there\n");

		if (r.data)
			free(r.data);
	}

	socket_close();
	return 0;
}
