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

struct lnode *database_get(unsigned long long id)
{
	pthread_mutex_lock(&lock);

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		if (fe->id == id){
			pthread_mutex_unlock(&lock);
			return cur;
		}
	}

	pthread_mutex_unlock(&lock);
	return 0;
}

void database_pop(struct lnode *node)
{
	pthread_mutex_lock(&lock);

	free(node->data);
	if (node == file_list)
		file_list = file_list->next;
	free(lnode_pop(node));

	pthread_mutex_unlock(&lock);
}

int database_rm(char *name)
{
	unsigned long long id = strtoull(name, 0, 16);
	struct lnode *node = database_get(id);

	if (!node)
		return 1;

	database_pop(node);
	cache_rm(id);

	char path[512];
	snprintf(path, 512, DATA_DIR "/database/%llx", id);
	remove(path);

	printf("%llx removed from database\n", id);

	return 0;
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

	struct lnode *n = database_get(id);

	if (n){
		entry = n->data;
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
	if (!config->db_persist)
		return 0;

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

	return 0;
}

void database_destroydb()
{
	if (config->db_persist)
		return;

	char name[256];

	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		serialize_id(fe->id, name, 256);
		remove(name);
	}
}

int database_flush()
{
	if (!config->db_persist)
		return 0;

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

int database_getstats(struct db_stats *stats)
{
	struct statvfs vfs;
	if (statvfs(DATA_DIR "/database/", &vfs))
		return 1;

	pthread_mutex_lock(&lock);
	for (struct lnode *cur = file_list; cur; cur = cur->next){
		struct file_entry *fe = cur->data;
		stats->files++;
		stats->disk_use += fe->len;
	}
	pthread_mutex_unlock(&lock);

	stats->disk_max = (vfs.f_bsize * vfs.f_bfree) + stats->disk_use;
	cache_getstats(stats);

	return 0;
}
