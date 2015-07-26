#include "sfh.h"

static struct lnode *threads;
static pthread_t cleaner_thread;
static pthread_mutex_t cleaner_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t threadlist_lock = PTHREAD_MUTEX_INITIALIZER;

void *cleaner()
{
	while(1){
		pthread_mutex_lock(&cleaner_lock);

		struct lnode *cur = threads;
		while (cur){
			struct lnode *temp = cur;
			struct thread_state *ts = cur->data;
			cur = cur->next;

			if (ts->terminated){
				pthread_join(ts->thread, 0);
				free(ts);
				pthread_mutex_lock(&threadlist_lock);
				free(lnode_pop(temp));
				if (temp == threads)
					threads = 0;
				pthread_mutex_unlock(&threadlist_lock);
			}
		}

		database_flush();

		pthread_mutex_unlock(&cleaner_lock);
		sleep(60);
	}
	pthread_exit(0);
}

void cleanup()
{
	pthread_mutex_lock(&cleaner_lock);
	pthread_mutex_lock(&threadlist_lock);

	pthread_cancel(cleaner_thread);
	pthread_join(cleaner_thread, 0);

	struct lnode *cur = threads;
	while (cur){
		struct lnode *temp = cur;
		struct thread_state *ts = cur->data;
		cur = cur->next;

		pthread_join(ts->thread, 0);
		free(ts);
		free(temp);
	}

	socket_terminate();
	database_terminate();
}

void sigterm()
{
	puts("Exiting gracefully");
	exit(0);
}

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

		snprintf(buf, 128, "http://" DOMAIN_NAME "/%llx\n", id);
		socket_puts(client_fd, buf);

		free(r.data);
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

		free(data);
	}else if (r.type == R_CACHED){
		char *http_header = "HTTP/1.0 304 Not Modified\r\n\r\n";

		if (!database_getfile(r.filename, 0)){
			socket_puts(client_fd, err_notfound);
			goto RET;
		}

		socket_puts(client_fd, http_header);
		printf("%s requested cached file\n", cc->str_addr);
	}

RET:
	shutdown(client_fd, SHUT_RDWR);
	close(client_fd);
	cc->ts->terminated = 1;
	free(cc);
	pthread_exit(0);
}

int main()
{
	if (socket_initialize()){
		puts("Failed to initialize server");
		return 1;
	}

	//Shrink user privileges
	struct passwd *pw = getpwnam(USERNAME);
	if (setuid(pw->pw_uid) == -1 || setgid(pw->pw_gid == (unsigned) -1)){
		puts("Failed to set user ID");
		return 1;
	}

	atexit(cleanup);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm;
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	database_init();

	pthread_create(&cleaner_thread, 0, cleaner, 0);

	while(1){
		struct client_ctx *cc = socket_nextclient();
		if (!cc)
			continue;

		struct lnode *n = calloc(sizeof(struct lnode), 1);
		struct thread_state *ts = calloc(sizeof(struct thread_state), 1);
		cc->ts = ts;

		pthread_create(&ts->thread, 0, process_request, (void *) cc);
		n->data = ts;
		pthread_mutex_lock(&threadlist_lock);
		threads = lnode_push(threads, n);
		pthread_mutex_unlock(&threadlist_lock);
	}

	exit(0);
}
