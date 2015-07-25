#include "sfh.h"

unsigned long long next_id;
struct lnode *file_list;

unsigned long long database_push(char *data, size_t len)
{
	struct lnode *n = calloc(sizeof(struct lnode), 1);
	struct file_entry *fe = calloc(sizeof(struct file_entry), 1);

	fe->data = data;
	fe->len = len;
	fe->id = next_id++;

	n->data = fe;
	file_list = lnode_push(file_list, n);

	return fe->id;
}

struct file_entry *database_getfile(char *name)
{
	unsigned long long id = strtoull(name, 0, 16);
	if (!id && errno == EINVAL){
		errno = 0;
		return 0;
	}

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		if (fe->id == id)
			return fe;
	}

	return 0;
}

void database_terminate()
{
	struct lnode *cur = file_list;

	while (cur){
		struct lnode *temp = cur;
		struct file_entry *fe = cur->data;

		cur = cur->next;

		free(fe->data);
		free(fe);
		free(temp);
	}
}
