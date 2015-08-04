#include "sfh.h"

struct socket{
	int fd;
	struct sockaddr_in addr;
};

static struct socket srv_http;
static struct socket srv_https;
static struct socket cli;

static pthread_t http_listener;
static pthread_t https_listener;

static pthread_cond_t avail_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t avail_lock = PTHREAD_MUTEX_INITIALIZER;

static const SSL_METHOD *method;
static SSL_CTX *ctx;

static struct lnode *client_queue;
static size_t queue_size;

void socket_clientaddr(struct client_ctx *cc)
{
	uint32_t addr = cli.addr.sin_addr.s_addr;

	memset(cc->str_addr, 0, 16);
	inet_ntop(AF_INET, &addr, cc->str_addr, 16);
}

void socket_close(struct client_ctx *cc)
{
	if (cc->ssl)
		SSL_free(cc->ssl);
	shutdown(cc->fd, SHUT_RDWR);
	close(cc->fd);
}

void socket_puts(struct client_ctx *cc, char *str)
{
	if (cc->ssl)
		SSL_write(cc->ssl, str, strlen(str));
	else
		write(cc->fd, str, strlen(str));
}

struct client_ctx *socket_listen(struct socket *s)
{
	socklen_t len = sizeof(struct sockaddr_in);
	int fd = accept(s->fd, (struct sockaddr *) &cli.addr, &len);
	if (fd == -1)
		return 0;

	struct client_ctx *cc = calloc(sizeof(*cc), 1);

	cc->fd = fd;
	socket_clientaddr(cc);

	return cc;
}

void queue_push(struct lnode *n, struct client_ctx *cc)
{
	if (queue_size >= SERVER_BACKLOG){
		socket_puts(cc, "Server too overloaded\n");
		free(cc);
		free(n);
		return;
	}

	pthread_mutex_lock(&avail_lock);

	n->data = cc;
	client_queue = lnode_push(client_queue, n);
	queue_size++;
	pthread_cond_signal(&avail_cond);

	pthread_mutex_unlock(&avail_lock);
}

struct client_ctx *queue_pop()
{
	pthread_mutex_lock(&avail_lock);

	if (!client_queue)
		pthread_cond_wait(&avail_cond, &avail_lock);

	struct lnode *n = lnode_pop(listend(client_queue));
	struct client_ctx *cc = n->data;
	queue_size--;
	free(n);

	if (n == client_queue)
		client_queue = 0;

	pthread_mutex_unlock(&avail_lock);

	return cc;
}

void *socket_http_listener()
{
	while (1){
		struct client_ctx *cc = socket_listen(&srv_http);
		if (!cc)
			continue;
		struct lnode *n = calloc(sizeof(*n), 1);

		queue_push(n, cc);
	}

	pthread_exit(0);
}

void *socket_https_listener()
{
	while (1){
		struct client_ctx *cc = socket_listen(&srv_https);
		if (!cc)
			continue;
		struct lnode *n = calloc(sizeof(*n), 1);

		cc->ssl = SSL_new(ctx);
		SSL_set_fd(cc->ssl, cc->fd);

		if (!cc->ssl || SSL_accept(cc->ssl) == -1){
			ERR_print_errors_fp(stderr);
			SSL_free(cc->ssl);
			cc->ssl = 0;
			socket_puts(cc, "Use HTTPS you fag\n");
			socket_close(cc);
			free(cc);
			free(n);
			continue;
		}

		queue_push(n, cc);
	}

	pthread_exit(0);
}

int socket_new(struct socket *s, uint16_t port)
{
	memset(&s->addr, 0, sizeof(s->addr));

	s->addr.sin_family = AF_INET;
	s->addr.sin_addr.s_addr = INADDR_ANY;
	s->addr.sin_port = htons(port);

	s->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (s->fd == -1)
		return 1;

	int optval = 1;
	setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (bind(s->fd, (struct sockaddr *) &s->addr, sizeof(s->addr)) == -1)
		return 1;

	if(listen(s->fd, SERVER_BACKLOG) == -1)
		return 1;

	return 0;
}

int socket_initialize()
{
	if (socket_new(&srv_http, config->port_http))
		return 1;
	if (socket_new(&srv_https, config->port_https))
		return 1;

	pthread_create(&http_listener, 0, socket_http_listener, 0);
	pthread_create(&https_listener, 0, socket_https_listener, 0);

	//Initialize OpenSSL
	char certpath[512];
	char pkeypath[512];
	snprintf(certpath, 512, CONF_DIR "/%s", config->ssl_cert);
	snprintf(pkeypath, 512, CONF_DIR "/%s", config->ssl_pkey);

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);

	if (!ctx){
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, pkeypath, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (!SSL_CTX_check_private_key(ctx)){
		puts("Key does not match certificate");
		return 1;
	}

	return 0;
}

struct client_ctx *socket_nextclient()
{
	struct client_ctx *cc = queue_pop();

	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, "%a %d/%m/%y %I:%M", localtime(&t));
	printf("\033[1m%s, (socket):\033[0m Got connection from %s\n", strtime, cc->str_addr);

	return cc;
}

void socket_terminate()
{
	pthread_mutex_lock(&avail_lock);

	pthread_cancel(http_listener);
	pthread_join(http_listener, 0);

	pthread_cancel(https_listener);
	pthread_join(https_listener, 0);

	close(srv_http.fd);
	close(srv_https.fd);

	SSL_CTX_free(ctx);
	ERR_remove_state(0);
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	SSL_COMP_free_compression_methods();
}

size_t socket_read_plain(struct client_ctx *cc, char *buf, size_t len)
{
	char *bufp = buf;
	char packet[PACKET_SIZE];
	size_t packetsize = 0;

	while ((size_t) (bufp - buf) < len && (packetsize = read(cc->fd, packet, PACKET_SIZE)) > 0){
		memcpy(bufp, packet, packetsize);
		bufp += packetsize;
	}

	return bufp - buf;
}

size_t socket_read(struct client_ctx *cc, char *buf, size_t len)
{
	if (!cc->ssl)
		return socket_read_plain(cc, buf, len);

	char *bufp = buf;
	char packet[PACKET_SIZE];
	size_t packetsize = 0;

	while ((size_t) (bufp - buf) < len && (packetsize = SSL_read(cc->ssl, packet, PACKET_SIZE)) > 0){
		memcpy(bufp, packet, packetsize);
		bufp += packetsize;
	}

	return bufp - buf;
}

void socket_write_plain(struct client_ctx *cc, char *buf, ssize_t len)
{
	size_t packetsize = 0;

	while (len > 0){
		packetsize = MIN(len, PACKET_SIZE);
		if (write(cc->fd, buf, packetsize) <= 0)
			break;
		buf += packetsize;
		len -= packetsize;
	}
}

void socket_write(struct client_ctx *cc, char *buf, ssize_t len)
{
	if (!cc->ssl){
		socket_write_plain(cc, buf, len);
		return;
	}

	size_t packetsize = 0;

	while (len > 0){
		packetsize = MIN(len, PACKET_SIZE);
		if (SSL_write(cc->ssl, buf, packetsize) <= 0)
			break;
		buf += packetsize;
		len -= packetsize;
	}
}

size_t socket_gets(struct client_ctx *cc, char *buf, size_t len)
{
	if (cc->ssl)
		return SSL_read(cc->ssl, buf, len);
	else
		return read(cc->fd, buf, len);
}
