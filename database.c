#include "sfh.h"

struct file_entry{
	size_t len;
	unsigned long long id;
};

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
unsigned long long next_id;
struct lnode *file_list;

int database_write(struct file_entry *fe, char *data)
{
	char name[256];
	snprintf(name, 256, DATABASE_DIR "/%llx", fe->id);

	FILE *fp = fopen(name, "wb");
	if (!fp)
		return 1;

	fwrite(data, 1, fe->len, fp);

	fclose(fp);
	return 0;
}

char *database_read(struct file_entry *fe)
{
	char *data;
	char name[256];
	snprintf(name, 256, DATABASE_DIR "/%llx", fe->id);

	FILE *fp = fopen(name, "rb");
	if (!fp)
		return 0;

	data = malloc(fe->len);
	fread(data, 1, fe->len, fp);

	fclose(fp);
	return data;
}

unsigned long long database_push(char *data, size_t len)
{
	struct lnode *n = calloc(sizeof(struct lnode), 1);
	struct file_entry *fe = calloc(sizeof(struct file_entry), 1);

	pthread_mutex_lock(&lock);

	fe->len = len;
	fe->id = next_id++;
	n->data = fe;
	file_list = lnode_push(file_list, n);

	pthread_mutex_unlock(&lock);

	database_write(fe, data);

	return fe->id;
}

size_t database_getfile(char *name, char **datap)
{
	struct file_entry *entry = 0;
	unsigned long long id = strtoull(name, 0, 16);
	if (!id && errno == EINVAL){
		errno = 0;
		return 0;
	}

	pthread_mutex_lock(&lock);

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;

		if (fe->id == id){
			entry = fe;
			break;
		}
	}

	pthread_mutex_unlock(&lock);

	if (entry){
		char *data = database_read(entry);

		if (!data)
			return 0;

		if (datap)
			*datap = data;

		return entry->len;
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

		free(fe);
		free(temp);
	}
}
