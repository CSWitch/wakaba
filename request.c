#include "sfh.h"

void process_admincmd(struct client_ctx *cc)
{
	char *cmd = cc->r->filename + 1;

	if (!config->admin_pwd[0]){
		socket_puts(cc, "Administration disabled (no password set)\n");
		return;
	}

	//Get and verify password.
	char pwd[128];
	char *pwd_delim = strchr(cmd, ':');
	size_t pwd_len = 0;
	if (!pwd_delim){
		socket_puts(cc, "Password required\n");
		return;
	}
	pwd_len = MIN(pwd_delim - cmd, 127);
	strncpy(pwd, cmd, pwd_len);
	pwd[pwd_len] = 0;

	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, "%a %d/%m/%y %I:%M", localtime(&t));

	if(strcmp(config->admin_pwd, pwd)){
		socket_puts(cc, "Access denied\n");
		printf("\033[1m%s, \033[31m(admin)\033[0;1m:\033[0m %s: Incorrect password (%s)\n", strtime, cc->str_addr, pwd);
		return;
	}
	cmd = pwd_delim + 1;

	printf("\033[1m%s, \033[31m(admin)\033[0;1m:\033[0m %s: \033[1mExecuted\033[0m command \"%s\"\n", strtime, cc->str_addr, cmd);

	char *err_inv = "Invalid syntax\n";

	//Process command.
	if (strstr(cmd, "stats") == cmd){ //Print stats.
		struct db_stats stats;
		memset(&stats, 0, sizeof(stats));
		char buf[1024];

		database_getstats(&stats);
		snprintf(buf, 1024,
				"Disk: %.2f/%.2f MB\n"
				"Cache: %.2f/%.2f MB\n"
				"Files: %zu (%zu cached)\n",
				(float) stats.disk_use / 1000000.0, (float) stats.disk_max / 1000000.0,
				(float) stats.cache_use / 1000000.0, (float) stats.cache_max / 1000000.0,
				stats.files, stats.cache_entries
		);
		socket_puts(cc, buf);
	}else if (strstr(cmd, "shutdown") == cmd){ //Shutdown server.
		socket_puts(cc, "Shutting down server\n");
		kill(getpid(), SIGTERM);
	}else if (strstr(cmd, "rm") == cmd){ //Remove file.
		char *name = strchr(cmd, '=');
		if (!name){
			socket_puts(cc, err_inv);
			return;
		}
		name++;

		if (database_rm(name)){
			socket_puts(cc, "File not found in database\n");
			return;
		}
		socket_puts(cc, "File removed from database\n");
	}else{ //Print help.
		socket_puts(cc,
				"Available commands:\n"
				"stats - print database statistics\n"
				"shutdown - gracefully terminate server\n"
				"rm - remove file from database\n"
		);
	}
}

void *process_request(void *p)
{
	char *err_invreq = "Invalid request\n";
	char *err_toolarge = "File too large\n";
	char *err_nodata = "No data received\n";
	char *err_notfound = "File not found in database\n";

	struct client_ctx *cc = p;
	struct request r;

	memset(&r, 0, sizeof(r));
	http_process_request(cc, &r);
	cc->r = &r;

	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, "%a %d/%m/%y %I:%M", localtime(&t));

	if (r.type == R_INVALID){
		switch(errno){
			case EFBIG:
				socket_puts(cc, err_toolarge);
				break;
			case ENODATA:
				socket_puts(cc, err_nodata);
				break;
			case EINVAL:
			default:
				socket_puts(cc, err_invreq);
				break;
		}
		errno = 0;
		goto RET;
	}

	if (r.type == R_CMD){
		process_admincmd(cc);
	}else if (r.type == R_POST){
		unsigned long long id = database_push(r.data, r.len);
		char buf[128];

		printf("\033[1m%s, (request):\033[0m %s: File of %zu bytes uploaded (%llx)\n", strtime, cc->str_addr, r.len, id);

		snprintf(buf, 128, "%s://%s:%i/%llx\n", cc->ssl ? "https" : "http", config->domainname, cc->ssl ? config->port_https : config->port_http, id);
		socket_puts(cc, buf);
	}else if (r.type == R_GET){
		char *data = 0;
		size_t len = database_getfile(r.filename, &data);
		char http_header[2048];

		if (!data){
			socket_puts(cc, err_notfound);
			goto RET;
		}

		printf("\033[1m%s, (request):\033[0m %s: File %s requested\n", strtime, cc->str_addr, r.filename);

		snprintf(http_header, 2048, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\nExpires: Sun, 17-jan-2038 19:14:07 GMT\r\n\r\n", len);
		socket_puts(cc, http_header);
		socket_write(cc, data, len);
	}else if (r.type == R_CACHED){
		char *http_header = "HTTP/1.0 304 Not Modified\r\n\r\n";

		if (!database_getfile(r.filename, 0)){
			socket_puts(cc, err_notfound);
			goto RET;
		}

		socket_puts(cc, http_header);
	}

RET:
	ERR_remove_state(0);
	socket_close(cc);
	cc->ts->terminated = 1;
	free(cc);
	pthread_exit(0);
}
