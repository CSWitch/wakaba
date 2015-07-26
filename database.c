#include "sfh.h"

struct file_entry{
	size_t len;
	unsigned long long id;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long next_id;
static struct lnode *file_list;

#define serialize_id(ID, BUF, LEN) {snprintf(BUF, LEN, DATA_DIR "database/%llx", ID);}

int database_write(struct file_entry *fe, char *data)
{
	char name[256];
	serialize_id(fe->id, name, 256);

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
	serialize_id(fe->id, name, 256);

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

	cache_push(data, len, fe->id);

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

	//Check the cache first.
	struct cache_entry *ce = cache_get(id);
	if (ce){
		if (datap)
			*datap = ce->data;
		return ce->len;
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

		//Put back in cache.
		if (!ce)
			cache_push(data, entry->len, entry->id);

		return entry->len;
	}

	return 0;
}

int database_isonfs(unsigned long long id)
{
	char name[256];
	serialize_id(id, name, 256);

	struct stat s;
	return (stat(name, &s) == 0);
}

int database_init()
{
#ifdef DATABASE_PERSIST
	FILE *fp = fopen(DATA_DIR "/database.txt", "r");
	if (!fp)
		return 1;

	while(!feof(fp)){
		struct lnode *n = calloc(sizeof(struct lnode), 1);
		struct file_entry *fe = calloc(sizeof(struct file_entry), 1);
		fscanf(fp, "%llx %zu\n", &fe->id, &fe->len);

		if (fe->len == 0 && fe->id == 0){ //Not a valid entry.
			free(n);
			free(fe);
			continue;
		}

		n->data = fe;
		file_list = lnode_push(file_list, n);
		next_id++;
	}
	fclose(fp);
#endif

	return 0;
}

void database_destroydb()
{
#ifndef DATABASE_PERSIST
	char name[256];

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		serialize_id(fe->id, name, 256);
		remove(name);
	}
	remove(DATA_DIR "database.txt");
#endif
}

int database_flush()
{
#ifdef DATABASE_PERSIST
	pthread_mutex_lock(&lock);
	FILE *fp = fopen(DATA_DIR "/database.txt", "w");
	if (!fp)
		return 1;

	for (struct lnode *cur = listend(file_list); cur; cur = cur->prev){
		struct file_entry *fe = cur->data;
		fprintf(fp, "%llx %zu\n", fe->id, fe->len);
	}

	fclose(fp);
	pthread_mutex_unlock(&lock);
#endif
	return 0;
}

void database_terminate()
{
	database_flush();
	database_destroydb();

	pthread_mutex_lock(&lock);
	struct lnode *cur = file_list;
	while (cur){
		struct lnode *temp = cur;
		struct file_entry *fe = cur->data;

		cur = cur->next;

		free(fe);
		free(temp);
	}
}
