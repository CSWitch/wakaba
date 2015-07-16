#include "sfh.h"

int main()
{
	if (socket_initialize()){
		puts("Error initializing server");
		return 1;
	}

	int client_fd;
	char msg[] = "Fuck off\n";

	while(1){
		client_fd = socket_nextclient();
		if (client_fd == -1)
			continue;

		printf("Got connection from %s\n", socket_clientaddr());
		write(client_fd, msg, strlen(msg));
	}

	socket_close();
	return 0;
}
