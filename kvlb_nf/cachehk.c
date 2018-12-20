#include <stdlib.h>
#include <string.h>

#include "cache_hk.h"

HT_PRIME_1 = 11;
HT_PRIME_2 = 79;

// cache config
CACHE_SIZE = 1;

static cached_kv DELETED_KV = {NULL, NULL};

// local cache structure implementation
static cached_kv*
cache_new_kv(const char* k, const char* v){
        cached_kv* kv = malloc(sizeof(cached_kv));
        kv->mc_key = strdup(k);
        kv->mc_value = strdup(v);

        return kv;
}

struct cache_hk*
cache_init(){
        cache_hk* cache = malloc(sizeof(cache_hk));

        cache->size = CACHE_SIZE;
        cache->count = 0;
        cache->kvs = calloc((size_t)cache->size, sizeof(cached_kv));

        return cache;
}

static void
cache_delete_kv(struct cached_kv* kv){
        free(kv->mc_key);
        free(kv->mc_value);
        free(kv);
}

void 
delete_cache(struct cache_hk* cache){
        
        for(int i = 0; i < cache->size; i++)
        {
                cached_kv* kv = cache->kvs[i];
                if(kv != NULL){
                        cache_delete_kv(kv);
                }
        }
        free(cache->kvs);
        free(cache);
}

static int
cache_hash(const char* s, const int a, const int m){
        long hash = 0;
        const int len_s = strlen(s);
        
        for(int i = 0; i < len_s; i++)
        {
                hash += (long)pow(a, len_s - (i + 1) * s[i]);
                hash = hash % m;
        }
        
        return (int)hash;
}

static int
cache_get_hash(const char* s, const int num_buckets, const int attempt) {
        const int hash_a = cache_hash(s, HT_PRIME_1, attempt);
        const int hash_b = cache_hash(s, HT_PRIME_2, attempt);

        return (hash_a + (attempt * (hash_b + 1))) % num_buckets;
}

void cache_insert(struct cache_hk* cache, const char* key, const char* value) {
        int i = 1;

        cached_kv* kv = cache_new_kv(key, value);
        int index = cache_get_hash(kv->mc_key, cache->size, 0);
        cached_kv* cur_kv = cache->kvs[index];

        while(cur_kv != NULL && cur_kv != &DELETED_KV){
            index = cache_get_hash(kv->mc_key, cache->size, i);
            cur_kv = cache->kvs[index];

            i++;
        }

        cache->kvs[index] = kv;
        cache->count++;

}


char* cache_search(struct cache_hk* cache, const char* key){
        int index = 0;
        int i = 1;

        index = cache_get_hash(key, cache->size, 0);
        cached_kv* kv = cache->kvs[index];

        while(kv != NULL){
            if (kv != &DELETED_KV) {
                if(strcmp(kv->mc_key, key) == 0){
                    return kv->mc_value;
            }
            index = cache_get_hash(key, cache->size, i);
            kv = cache->kvs[index];

            i++;
            }
        }
        return NULL;
}


void cache_delete(struct cache_hk* cache, const char* key){
        int index = 0;
        int i = 1;

        index = cache_get_hash(key, cache->size, 0);
        cached_kv* kv = cache->kvs[index];

        while(kv != NULL) {
            if (kv != &DELETED_KV) {
                if (strcmp(kv->mc_key, key) == 0) {
                    cache_delete_kv(kv);
                    cache->kvs[index] = &DELETED_KV;
                }
            }
            index = cache_get_hash(key, cache->size, i);
            kv = cache->kvs[index];

            i++;
        }
}


cache_hk* 
cache_clear(struct cache_hk* cache){
        cache_hk* new_cache;

        delete_cache(cache);
        new_cache = cache_init();
}