#include "sfh.h"

static struct lnode *threads;
static pthread_t cleaner_thread;
static pthread_mutex_t cleaner_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t threadlist_lock = PTHREAD_MUTEX_INITIALIZER;

static struct config conf = {
	.port_http = 8080,
	.port_https = 4433,
	.max_file_size = 32000000, //32 MB
	.max_cache_size = 512000000, //512 MB
	.domainname = "wakaba.dhcp.io",
	.username = "wakaba",
	.db_persist = 0,
	.browser_cache = 0,
	.ssl_cert = "server.crt",
	.ssl_pkey = "server.key",
	.admin_pwd = ""
};

void *cleaner()
{
	prctl(PR_SET_NAME, (char *)"GC", 0, 0, 0);

	while(1){
		pthread_mutex_lock(&cleaner_lock);

		int count = 0;
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
				count++;
			}
		}

		if (count > 0){
			char strtime[512];
			time_t t = time(0);
			strftime(strtime, 512, TIME_FORMAT, localtime(&t));
			printf("\033[1m%s, (GC):\033[0m Cleaned up %i %s\n", strtime, count, count > 1 ? "threads" : "thread");
		}

		socket_writebans();
		database_flush();
		cache_prune();

		pthread_mutex_unlock(&cleaner_lock);
		sleep(60);
	}
	pthread_exit(0);
}

void cleanup()
{
	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, TIME_FORMAT, localtime(&t));
	printf("\033[1m%s, (server):\033[0m Server shutting down\n", strtime);

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
	cache_terminate();
}

void sigterm()
{
	exit(0);
}

void sigsegv()
{
	void *bt[20];
	size_t len = backtrace(bt, 20);

	fputs("Killed by SIGSEGV, fix your fucking program:\n", stderr);
	backtrace_symbols_fd(bt, len, STDERR_FILENO);
	exit(1);
}

int load_config()
{
	FILE *fp = fopen(CONF_DIR "wakaba.conf", "r");
	if (!fp)
		return 1;

	char opt[128];
	char val[128];

	while (!feof(fp)){
		memset(opt, 0, 128);
		memset(val, 0, 128);

		fscanf(fp, "%s = %s\n", opt, val);
		if (!opt[0] || !val[0] || isspace(opt[0]) || opt[0] == '#')
			continue;

		if (!strcmp(opt, "port_http")){
			config->port_http = (uint16_t) strtol(val, 0, 10);
		}else if (!strcmp(opt, "port_https")){
			config->port_https = (uint16_t) strtol(val, 0, 10);
		}else if (!strcmp(opt, "max_file_size")){
			config->max_file_size = (size_t) strtol(val, 0, 10);
		}else if (!strcmp(opt, "max_cache_size")){
			config->max_cache_size = (size_t) strtol(val, 0, 10);
		}else if (!strcmp(opt, "domainname")){
			strncpy(config->domainname, val, 128);
		}else if (!strcmp(opt, "username")){
			strncpy(config->username, val, 128);
		}else if (!strcmp(opt, "db_persist")){
			config->db_persist = (char) strtol(val, 0, 10);
		}else if (!strcmp(opt, "browser_cache")){
			config->browser_cache = (char) strtol(val, 0, 10);
		}else if (!strcmp(opt, "ssl_cert")){
			strncpy(config->ssl_cert, val, 128);
		}else if (!strcmp(opt, "ssl_pkey")){
			strncpy(config->ssl_pkey, val, 128);
		}else if (!strcmp(opt, "admin_pwd")){
			strncpy(config->admin_pwd, val, 128);
		}
	}

	fclose(fp);
	return 0;
}

int main()
{
	//Piping stdout to a file disables line buffering, so turn it back on.
	setvbuf(stdout, 0, _IOLBF, 0);

	config = &conf;
	load_config();

	if (socket_initialize()){
		puts("\033[1;31mERROR:\033[0m Failed to initialize server");
		return 1;
	}

	//Shrink user privileges
	struct passwd *pw = getpwnam(config->username);
	if (!pw || setuid(pw->pw_uid) == -1){
		printf("\033[1;31mERROR:\033[0m Failed to set user to \"%s\"\n", config->username);
		return 1;
	}

	atexit(cleanup);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = sigterm;
	sigaction(SIGTERM, &sa, 0);
	sigaction(SIGINT, &sa, 0);

	sa.sa_handler = sigsegv;
	sigaction(SIGSEGV, &sa, 0);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, 0);

	database_init();

	pthread_create(&cleaner_thread, 0, cleaner, 0);

	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, TIME_FORMAT, localtime(&t));
	printf("\033[1m%s, (server):\033[0m Server initialized\n", strtime);

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
