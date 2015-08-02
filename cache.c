#include "sfh.h"

static struct lnode *cache_list;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void cache_push(char *data, size_t len, unsigned long long id)
{
	struct lnode *n = calloc(sizeof(*n), 1);
	struct cache_entry *ce = calloc(sizeof(*ce), 1);

	ce->data = data;
	ce->len = len;
	ce->id = id;

	pthread_mutex_lock(&lock);
	n->data = ce;
	cache_list = lnode_push(cache_list, n);
	pthread_mutex_unlock(&lock);
}

struct lnode *cache_get_node(unsigned long long id)
{
	pthread_mutex_lock(&lock);

	for (struct lnode *cur = cache_list; cur; cur = cur->next){
		struct cache_entry *ce = cur->data;

		if (ce->id == id){
			pthread_mutex_unlock(&lock);
			return cur;
		}
	}

	pthread_mutex_unlock(&lock);
	return 0;
}

struct cache_entry *cache_get(unsigned long long id)
{
	struct lnode *n = cache_get_node(id);

	if (n)
		return n->data;

	return 0;
}

void cache_pop(struct lnode *n)
{
	struct cache_entry *ce = n->data;
	free(ce->data);
	free(ce);
	if (n == cache_list)
		cache_list = cache_list->next;
	free(lnode_pop(n));
}

int cache_rm(unsigned long long id)
{
	struct lnode *n = cache_get_node(id);

	if (n){
		pthread_mutex_lock(&lock);
		cache_pop(n);
		pthread_mutex_unlock(&lock);

		return 0;
	}

	return 1;
}

void cache_prune()
{
	pthread_mutex_lock(&lock);

	size_t freed = 0;
	size_t size = 0;
	struct lnode *cur = cache_list;
	while (cur){
		struct lnode *temp = cur;
		struct cache_entry *ce = cur->data;
		cur = cur->next;

		size += ce->len;

		if (size > config->max_cache_size){
			cache_pop(temp);
			freed += ce->len;
		}
	}

	if (freed > 0){
		char strtime[512];
		time_t t = time(0);
		strftime(strtime, 512, "%a %d/%m/%y %I:%M", localtime(&t));
		printf("\033[1m%s, (GC):\033[0m Pruned %zu bytes from cache\n", strtime, freed);
	}

	pthread_mutex_unlock(&lock);
}

void cache_terminate()
{
	pthread_mutex_lock(&lock);

	struct lnode *cur = cache_list;
	while(cur){
		struct lnode *temp = cur;
		struct cache_entry *ce = cur->data;
		cur = cur->next;
		free(ce->data);
		free(ce);
		free(temp);
	}
}

void cache_getstats(struct db_stats *stats)
{
	stats->cache_max = config->max_cache_size;

	pthread_mutex_lock(&lock);
	for (struct lnode *cur = cache_list; cur; cur = cur->next){
		struct cache_entry *ce = cur->data;
		stats->cache_entries++;
		stats->cache_use += ce->len;
	}
	pthread_mutex_unlock(&lock);
}
