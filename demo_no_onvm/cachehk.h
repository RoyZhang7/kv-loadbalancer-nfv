#ifndef CACHEHK_H
#define CACHEHK_H

#include <math.h>

// hash table cache
typedef struct cached_kv
{
        char* mc_key;
        char* mc_value;
} cached_kv;

typedef struct cache_hk
{
        int size;
        int count;
        cached_kv** kvs;
} cache_hk;

static cache_hk* cache_init();
void cache_insert(struct cache_hk* cache, const char* key, const char* value);
char* cache_search(struct cache_hk* cache, const char* key);
void cache_delete(struct cache_hk* cache, const char* key);
static cache_hk* cache_clear(struct cache_hk* cache);

#endif