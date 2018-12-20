#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "hktable.h"
#include "cachehk.h"

static hotkey DELETED_HK = {NULL, NULL};

static hotkey*
hkt_new_hotkey(char* key, char* value){
        hotkey* hk = malloc(sizeof(hotkey));
        hk->mc_key = key;
        hk->mc_value = value;
        hk->lossy_counter = 1;
}

static hk_table*
hk_table_init(int table_size, int lossy_window_size){
        hk_table* hkt = malloc(sizeof(hk_table));

        hkt->ht_table_size = table_size;
        hkt->num_stored = 0;
        hkt->hks = calloc((size_t)hkt->ht_table_size, sizeof(hotkey));

        hkt->lossy_window_size = lossy_window_size;
        hkt->elapsed_couter = 0;
        hkt->elapsed_window = 0;

        hkt->frequency = 0.2;
        hkt->error = 0.02;

        hkt->is_ht_detected = 0;

        return hkt;
}

static void
hkt_delete_hk(struct hotkey* hk){
        free(hk->mc_key);
        free(hk->mc_value);
        // do not need to free lossy counter here
        free(hk);
}

void
delete_hkt(struct hk_table* hkt){
        int i;
        for(i = 0; i < hkt->ht_table_size; i++)
        {
                hotkey* hk = hkt->hks[i];
                
                if (hk != NULL) {
                        hkt_delete_hk(hk);
                }
                
        }
        free(hkt->hks);
        free(hkt);
}

static int
hkt_hash(char* s, int a, int m){
        int i;
        long hash = 0;
        int len_s = strlen(s);
        
        for( i = 0; i < len_s; i++)
        {
                hash += (long)pow(a, len_s - (i + 1) * s[i]);
                hash = hash % m;
        }
        
        return (int)hash;
}

static int
hkt_get_hash( char* s, int num_buckets,  int attempt) {
        int hash_a = hkt_hash(s, 127, attempt);
        int hash_b = hkt_hash(s, 83, attempt);

        return (hash_a + (attempt * (hash_b + 1))) % num_buckets;
}

static void 
hkt_insert(struct hk_table* hkt, char* key, char* value) {
        int i = 1;

        hotkey* hk = (hotkey*)hkt_new_hotkey(key, value);
        int index = hkt_get_hash(hk->mc_key, hkt->ht_table_size, 0);
        hotkey* cur_kv = hkt->hks[index];

        while(cur_kv != NULL){
                if (cur_kv != &DELETED_HK) {
                        if(strcmp(cur_kv->mc_key, key) == 0){
                                hkt_delete_hk(cur_kv);
                                hkt->hks[i] = hk;
                                return;
                        }
                        index = hkt_get_hash(hk->mc_key, hkt->ht_table_size, i);
                        cur_kv = hkt->hks[index];

                        i++;
                }
        }

        hkt->hks[index] = hk;
        hkt->num_stored++;
}

char*
hkt_search(struct hk_table* hkt, char* key){
        int index = 0;
        int i = 1;

        index = hkt_get_hash(key, hkt->ht_table_size, 0);
        hotkey* hk = hkt->hks[index];

        while(hk != NULL){
            if (hk != &DELETED_HK) {
                if(strcmp(hk->mc_key, key) == 0){
                    index = hkt_get_hash(key, hkt->ht_table_size, i);
                    return hk->mc_value;
                    // return index;
            }
            index = hkt_get_hash(key, hkt->ht_table_size, i);
            hk = hkt->hks[index];
            // return index;
            
            i++;
            }
        }
        return NULL;
}


static int
hkt_getindex(struct hk_table* hkt, char* key){
        int index = 0;
        int i = 1;

        printf("in hkt_getindex()--key: %s\n", key);

        index = hkt_get_hash(key, hkt->ht_table_size, 0);
        hotkey* hk = hkt->hks[index];

        printf("got hash for key: %d\n", index);

        while(hk != NULL){
            if (hk != &DELETED_HK) {
                if(strcmp(hk->mc_key, key) == 0){
                    index = hkt_get_hash(key, hkt->ht_table_size, i);
                    // return hk->mc_value
                    return index;
            }
            index = hkt_get_hash(key, hkt->ht_table_size, i);
            // hk = hkt->hks[index];
            return index;
            
            i++;
            }
        }
        return -1;
}

static void 
hkt_delete(struct hk_table* hkt, char* key){
        int index = 0;
        int i = 1;

        index = hkt_get_hash(key, hkt->ht_table_size, 0);
        hotkey* hk = hkt->hks[index];

        while(hk != NULL) {
            if (hk != &DELETED_HK) {
                if (strcmp(hk->mc_key, key) == 0) {
                    hkt_delete_hk(hk);
                    hkt->hks[index] = &DELETED_HK;
                }
            }
            index = hkt_get_hash(key, hkt->ht_table_size, i);
            hk = hkt->hks[index];

            i++;
        }
}

void
hkt_hks_freq_decr(struct hk_table* hkt){
        int i;
        for( i = 0; i < hkt->ht_table_size; i++) {
                hotkey* hk = hkt->hks[i];
                if (hk != NULL) {
                        hk->lossy_counter--;
                }
        }
}

//TODO: insert sort before cache_insert
static void
hkt_filter_above_threshold(struct hk_table* hkt, cache_hk* cache,float threshold){
        int i;

        cache_hk* new_cache = cache_clear(cache);
        for(i = 0; i < hkt->ht_table_size; i++) {
                if (i <= cache->size) {
                    hotkey* hk = hkt->hks[i];
                    hk->lossy_counter--;
                    if (hk->lossy_counter > threshold) {
                            cache_insert(new_cache, hk->mc_key, hk->mc_value);
                    }
                }

        }
}