#include "sfh.h"

char *http_get_field(char *buf, char *name)
{
	char *attr = 0;
	char *val = 0;

	attr = strstr(buf, name);
	if (!attr)
		return 0;

	val = strchr(attr, ':');
	if (!val)
		return 0;
	val += 2;

	return val;
}

size_t http_get_header(char *buf, char *header, size_t n)
{
	char *end = strstr(buf, "\r\n\r\n");
	size_t len = 0;

	if (!end)
		return 0;
	end += 4;

	len = MIN((size_t) (end - buf), n - 1);
	memcpy(header, buf, len);
	header[len] = 0;

	return len;
}

void http_process_request(int fd, struct request *r)
{
	char header[512];
	char *buf = malloc(512);
	size_t header_len;
	size_t buf_len = 0;

	buf_len = read(fd, buf, 512);
	if (!buf_len)
		goto ERROR;

	//Some (retarded) browsers (like Firefox) like to send the body in the same packet as the header, so:
	//Move header into it's own buffer, and move body to front of buf.
	header_len = http_get_header(buf, header, 512);
	buf_len -= header_len;
	memmove(buf, buf + header_len, buf_len);

	if (strstr(header, "GET") == header){
		r->type = R_GET;
		free(buf);
	}else if (strstr(header, "POST") == header){
		r->type = R_POST;
	}

	if (r->type == R_POST){
		//Make sure header sends Content-Length.
		size_t content_length = strtol(http_get_field(header, "Content-Length: "), 0, 10);
		if (!content_length)
			goto ERROR;

		//Expand buf and read in rest of the body.
		buf = realloc(buf, content_length);
		buf_len += socket_read(fd, buf + buf_len, content_length - buf_len);

		//I wouldn't trust it, considering most of these requests are coming from /g/.
		if (buf_len != content_length)
			goto ERROR;

		r->len = buf_len;
		r->data = buf;

		//TODO: Parse form and get file data.

	}else if (r->type == R_GET){
		//TODO: Grab filename.
	}

	return;
ERROR:
	r->type = R_INVALID;
	return;
}
