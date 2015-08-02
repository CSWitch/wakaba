#include "sfh.h"

static int server_fd;
static struct sockaddr_in server_addr;

static int client_fd;
static struct sockaddr_in client_addr;
static socklen_t client_len = sizeof(struct sockaddr_in);

//SSL stuff
static const SSL_METHOD *method;
static SSL_CTX *ctx;

int socket_initialize()
{
	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(config->port);

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1)
		return 1;

	int optval = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1)
		return 1;

	if(listen(server_fd, SERVER_BACKLOG) == -1)
		return 1;

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

void socket_clientaddr(struct client_ctx *cc)
{
	uint32_t addr = client_addr.sin_addr.s_addr;

	memset(cc->str_addr, 0, 16);
	inet_ntop(AF_INET, &addr, cc->str_addr, 16);
}

void socket_close(struct client_ctx *cc)
{
	SSL_free(cc->ssl);
	shutdown(cc->fd, SHUT_RDWR);
	close(cc->fd);
}

void socket_close_plain(struct client_ctx *cc)
{
	shutdown(cc->fd, SHUT_RDWR);
	close(cc->fd);
}

void socket_puts_plain(struct client_ctx *cc, char *str)
{
	write(cc->fd , str, strlen(str));
}


struct client_ctx *socket_nextclient()
{
	struct client_ctx *cc;

	client_fd = accept(server_fd, (struct sockaddr *)  &client_addr, &client_len);
	if (client_fd == -1)
		return 0;

	cc = calloc(sizeof(*cc), 1);
	cc->fd = client_fd;
	socket_clientaddr(cc);

	char strtime[512];
	time_t t = time(0);
	strftime(strtime, 512, "%a %d/%m/%y %I:%M", localtime(&t));
	printf("\033[1m%s, (socket):\033[0m Got connection from %s\n", strtime, cc->str_addr);

	//SSL
	cc->ssl = SSL_new(ctx);
	SSL_set_fd(cc->ssl, cc->fd);

	if (SSL_accept(cc->ssl) == -1){
		ERR_print_errors_fp(stderr);
		SSL_free(cc->ssl);
		socket_puts_plain(cc, "Use HTTPS you fag\n");
		socket_close_plain(cc);
		free(cc);
		return 0;
	}

	return cc;
}

void socket_terminate()
{
	close(server_fd);
	SSL_CTX_free(ctx);
	ERR_remove_state(0);
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	SSL_COMP_free_compression_methods();
}

void socket_puts(struct client_ctx *cc, char *str)
{
	SSL_write(cc->ssl, str, strlen(str));
}

size_t socket_read(struct client_ctx *cc, char *buf, size_t len)
{
	char *bufp = buf;
	char packet[PACKET_SIZE];
	size_t packetsize = 0;

	while ((size_t) (bufp - buf) < len && (packetsize = SSL_read(cc->ssl, packet, PACKET_SIZE)) > 0){
		memcpy(bufp, packet, packetsize);
		bufp += packetsize;
	}

	return bufp - buf;
}

void socket_write(struct client_ctx *cc, char *buf, ssize_t len)
{
	size_t packetsize = 0;

	while (len > 0){
		packetsize = MIN(len, PACKET_SIZE);
		if (SSL_write(cc->ssl, buf, packetsize) <= 0)
			break;
		buf += packetsize;
		len -= packetsize;
	}
}
