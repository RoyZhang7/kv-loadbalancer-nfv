#ifndef HKTABLE_H
#define HKTABLE_H

#include <stdint.h>
#include <math.h>
#include "./cachehk.h"

typedef struct hotkey
{
        //memcached kv
        char* mc_key;
        char* mc_value;

        unsigned int lossy_counter;
} hotkey;

/* struct definition */
typedef struct hk_table
{
        int ht_table_size;
        int num_stored;

        // hot keys
        hotkey** hks;

        // window size and stream counter
        int lossy_window_size;
        int elapsed_window;
        int elapsed_couter;
        int lossy_total;

        // lossy counting threshold
        float frequency;
        float error;

        int is_ht_detected;
} hk_table;



/* func declearition */
static hk_table* hk_table_init(int table_size, int lossy_window_size);
static hotkey* hkt_new_hotkey(char* key, char* value);
static void  hkt_insert(struct hk_table* hkt, char* key, char* value) ;
char* hkt_search(struct hk_table* hkt, char* key);
static int hkt_getindex(struct hk_table* hkt, char* key);
static void hkt_delete(struct hk_table* hkt, char* key);
void hkt_hks_freq_decr(struct hk_table* hkt);
static void hkt_filter_above_threshold(struct hk_table* hkt, cache_hk* cache,float threshold);

#endif