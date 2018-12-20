#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "./cachehk.h"
#include "./hktable.h"


void rand_str(char *, size_t);

// extern inline hk_table* hk_table_init(int table_size, int lossy_window_size);
// extern inline hotkey* hkt_new_hotkey(char* key, char* value);
// extern inline void  hkt_insert(struct hk_table* hkt, char* key, char* value) ;
// extern inline int hkt_getindex(struct hk_table* hkt, char* key);
// extern inline void hkt_delete(struct hk_table* hkt, char* key);
// extern inline void hkt_filter_above_threshold(struct hk_table* hkt, cache_hk* cache,float threshold);
// extern inline cache_hk* cache_init();
// extern inline cache_hk* cache_clear(struct cache_hk* cache);

static int hotkey_output(void);
static int hotkey_lookup(char*, char*);
static int hotkey_freq_decrease(void);
static int hotkey_detector(struct hotkey*);
void packet_handler(char *);

struct hk_table *hkt;
struct hotkey *hk;
struct cache_hk *cache;
struct cached_kv *c_kv;


int main(int argc, char const *argv[])
{
    int i;
    char test_key[40];
    int lossy_total;
    int lossy_window_size;
    int table_size;
    
    lossy_total = atoi(argv[1]);
    lossy_window_size = atoi(argv[2]);
    table_size = atoi(argv[3]);

    printf("lossy total: %d\n", lossy_total);
    printf("lossy window: %d\n", lossy_window_size);
    printf("table size: %d\n", table_size);

    hkt = hk_table_init(table_size, lossy_window_size);
    cache = cache_init();

    if(hkt == NULL || cache == NULL){
        printf("init hkt or cache failed");
        return -1;
    }

    hkt->lossy_total = lossy_total;

    for( i = 0; i < lossy_total; i++)
    {
        rand_str(test_key, 40);
        printf("the #%d random key: %s\n", i, test_key);
        packet_handler(test_key);
    }

    printf("detected hotkeys are:");
    
    for( i = 0; i < cache->count; i++)
    {
        printf("the #%d hot key\n", i);
        printf("key--%s\n", cache->kvs[i]->mc_key);
        printf("value--%s\n", cache->kvs[i]->mc_value);
    }
    

    return 0;
}

void rand_str(char* dest, size_t length){
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}


/* output the hotkey table to local cache, and reset all counter */
static int
hotkey_output(void){
        int threshold = 0;

        // compute hotkey for first time 
        if (hkt->is_ht_detected == 0 && cache->count == 0) {
                if (cache == NULL) {
                    printf("error occur when create local cache\n");
                    return -1;
                }
        // later 
        } else {
                cache = cache_clear(cache);
                if (cache == NULL) {
                    printf("error occur when clear local cache\n");
                    return -1;
                }
        }

        // calculate lossy counting threshold
        threshold = (hkt->frequency - hkt->error) * hkt->num_stored;

        // outs all hot key, write into cache
        hkt_filter_above_threshold(hkt, cache, threshold);

        // cache write fail
        if (cache->kvs[0] != NULL) {
                printf("cache write failed\n");
                return -1;
        }

        hkt->is_ht_detected = 1;

        // reset varible for start next round of lossy counting 
        hkt->num_stored = 0;
        hkt->elapsed_couter = 0;

        return 0;
}

/* look hotkey in hotkey table */
static int
hotkey_lookup(char *k, char *v){
        int index = 0;

        printf("looking up for key: %s\n", k);

        index = hkt_getindex(hkt, k);
        printf("got index for key: %d\n", index);
        // cannot find -- new key
        if ( index == -1 ) {
                hkt_insert(hkt, k, "");
        // find a key without value, then we assign it
        } else if( index != -1 || hkt->hks[index]->mc_value[0] == '\0' || v[0] != '\0' ) { 
                strcpy(hkt->hks[index]->mc_value, v);
                hkt->hks[index]->lossy_counter ++;
        } else {
                hkt->hks[index]->lossy_counter ++;
        }

        return 0;
}


/* decrease counter when reach window boudary */
static int
hotkey_freq_decrease(void){
        int i;

        // interate all hot key in hotkey table, decrease each by 1
        for(i = 0; i < hkt->num_stored; i++)
        {
                hkt->hks[i]->lossy_counter --;
                // drop the hotkey if frequency reaches 1
                if (hkt->hks[i]->lossy_counter == 1) {
                    hkt_delete(hkt, hkt->hks[i]->mc_key);
                }
        }
        return 0;
}

/* detecte hot key */
static int
hotkey_detector(struct hotkey* hk){
        int ret;

        // lossy counting
        hkt->elapsed_couter ++;

        // window boundary
        if (hkt->elapsed_couter > hkt->lossy_window_size) {
                hotkey_freq_decrease();
                hkt->elapsed_couter = 0;
                hkt->elapsed_window ++;

                // round boundary
                if ((hkt->elapsed_window * hkt->lossy_window_size) + 1 > hkt->ht_table_size) {
                    hotkey_output();
                }
        } else {
                // look up given hot key, if not found then add
                ret = hotkey_lookup(hk->mc_key, hk->mc_value);
                if (ret == -1) {
                        printf("Error occur when lookup the memcached key in hotkey table\n");
                        return -1;
                }
        }

        
        return 0;
}


void packet_handler(char* key){
    // hot key havent been detected
    if(hkt->is_ht_detected == 0){
        /* handle packet using flow table */
        /* ignore this part */
        // pretend to have flow table here
        // lookup in flow table: 
        // if found then change packet info, 
        // if not found then add entry(if table full, then clear)
        // use flow table handling all packet that contains cold mckey
        // if the packet is from server, store unknown key-value

        hk = hkt_new_hotkey(key, "");

        hotkey_detector(hk);
        /* hot key detector */
        // for all packet, parse memcached key from packet, lookup mckey
        // if found value, then send back to client using udp, frequency of the key ++
        // if not found, then add entry in hot key table, set frequency as 1
        // when counter == window size, then decrease all frequency by 1, drop any key has frequency less than 2. set counter to 0 again
        // repeat above steps, until we finish a round of N element. 
        // outs hotkeys that freq > 0.2N - 0.02N, write hotkeys into cache



    } 
    else
    {
        /* cached hoykey */
        // once cache exists, look up cache first.
        // cache hit, then send kv back using udp
        // cache miss, use flow talbe handle it
        printf("if we reach here, hot key has been detected");
    }
    
}
