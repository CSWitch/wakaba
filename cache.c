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

struct cache_entry *cache_get(unsigned long long id)
{
	pthread_mutex_lock(&lock);

	for (struct lnode *cur = cache_list; cur; cur = cur->next){
		struct cache_entry *ce = cur->data;

		if (ce->id == id){
			pthread_mutex_unlock(&lock);
			return ce;
		}
	}

	pthread_mutex_unlock(&lock);
	return 0;
}

void cache_pop(struct lnode *n)
{
	struct cache_entry *ce = n->data;
	free(ce->data);
	free(ce);
	if (n == cache_list)
		cache_list = 0;
	free(lnode_pop(n));
}

void cache_prune()
{
	pthread_mutex_lock(&lock);

	size_t size = 0;
	struct lnode *cur = cache_list;
	while (cur){
		struct lnode *temp = cur;
		struct cache_entry *ce = cur->data;
		cur = cur->next;

		size += ce->len;

		if (size > config->max_cache_size)
			cache_pop(temp);
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
