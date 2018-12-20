#ifndef HKTABLE_H
#define HKTABLE_H

#include <stdint.h>

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
        uint16_t ht_table_size;
        int num_stored;

        // hot keys
        hotkey** hks;

        // window size and stream counter
        uint16_t lossy_window_size;
        int elapsed_window;
        int elapsed_couter;

        // lossy counting threshold
        float frequency;
        float error;

        int is_ht_detected;
} hk_table;



/* func declearition */
void hkt_insert(struct hk_table* hkt, const char* key, const char* value);
char* hkt_search(struct hk_table* hkt, const char* key);
int hkt_getindex(struct hk_table* hkt, const char* key);
void hkt_delete(struct hk_table* hkt, const char* key);
void hkt_hks_freq_decr(struct hk_table* hkt);
void hkt_filter_above_threshold(struct hk_table* hkt, float threshold);

#endif