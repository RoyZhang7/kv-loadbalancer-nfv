/*********************************************************************
 * kv_loadbalancer.c - kvlb NF for research project.
 *
 * A. before hotkey table generated:
 *      1. drop non-udp packet
 *      2. set kvlb'ip to server or client repesctly
 *      3. get packet flow entry
 *          - if new, save
 *          - if old, send based on flow table
 *      4. detect hotkey, store in cache
 *      5. recalculate checksums
 * 
 * B. after hotkey table generated:
 *      1. if cache hit, return it to client directly
 *      2. if cache miss, repeat steps in A
 *      3. detect hotkey, store in cache
 ********************************************************************/
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_memory.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_flow_table.h"

#include "cachehk.h"
#include "hktable.h"

#define NF_TAG "kv_loadbalancer"

/* table size */
#define FLOW_TABLE_SIZE 65536
#define HOTKEY_TABLE_SIZE 1000
#define MCKEY_LEN 250 //max key length in Memcached is 250 character
#define MCVALUE_LEN 1024 

/* struct def */
struct kvloadbalancer
{
        // flow table
        struct onvm_ft *ft;

        // server
        struct server *server;
        uint8_t number_of_server;

        uint16_t num_stored;
        uint64_t elapsed_cycles;
        uint64_t last_cycles;
        uint32_t expire_time;

        // port and ip_addr
        uint32_t ip_kvlb_server;
        uint32_t ip_kvlb_client;
        uint8_t port_server;
        uint8_t port_client;

        // interface names
        char * client_iface_name;
        char * server_iface_name;

        // config file
        char * cfg_filename;
};

struct server
{
        uint8_t server_addr_bytes[ETHER_ADDR_LEN];
        uint32_t server_ip;
};

struct flow_info
{
        uint8_t dest;
        uint8_t source_addr_bytes[ETHER_ADDR_LEN];
        uint64_t last_pkt_cycles;
        int is_active;
};


/* struct declarition */
struct onvm_nf_info *nf_info; // struct for information about this NF

struct kvloadbalancer *kvlb;

struct hk_table *hkt;
struct cache_hk *cache;
struct cached_kv *c_kv;

extern struct prot_info *ports;

struct ether_hdr;
struct ipv4_hdr;
struct udp_hdr;

/* varibles declarition */
static uint32_t print_delay = 1000000; // number of package between each print


/**************************************************/
/*********** main func related function ***********/
/**************************************************/
/* Print a usage message */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- client_iface server_iface server_config -p <print_delay>\n\n", progname);
}


/* Parse the application arguments */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;
        
        kvlb->cfg_filename = NULL;
        kvlb->client_iface_name = NULL;
        kvlb->server_iface_name = NULL;

        while ((c = getopt(argc, argv, "c:s:f:p:")) != -1) {
                switch (c) {
                case 'c':
                        kvlb->client_iface_name = strdup(optarg);
                        break;
                case 's':
                        kvlb->server_iface_name = strdup(optarg);
                        break;
                case 'f':
                        kvlb->cfg_filename = strdup(optarg);
                        break;
                case 'w':
                        hkt->lossy_window_size = strtoul(optarg, NULL, 10);
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!kvlb->cfg_filename) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a backend server config file.\n");
                return -1;
 
        if (!kvlb->client_iface_name) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a client interface name.\n");
                return -1;
        }
        if (!kvlb->server_iface_name) {
                RTE_LOG(INFO, APP, "Load balancer NF requires a backend server interface name.\n");
                return -1;
        }       }

        return optind;
}


/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N掳   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}


/* print flow info */
static void
print_flow_info(struct flow_info *f){
        printf("Flow Info\n");
        printf("Destination server: %d\n", f->dest);
        printf("Source mac %02x:%02x:%02x:%02x:%02x:%02x\n",
                f->source_addr_bytes[0], f->source_addr_bytes[1],
                f->source_addr_bytes[2], f->source_addr_bytes[3],
                f->source_addr_bytes[4], f->source_addr_bytes[5]);
}


/*
 * This function parses the backend config. It takes the filename 
 * and fills up the server array. This includes the mac and ip 
 * address of the backend servers
 */
static int
parse_backend_config(void) {
        int ret, temp, i;
        char ip[32];
        char mac[32];
        FILE * cfg;

        cfg  = fopen(kvlb->cfg_filename, "r");
        if (cfg == NULL) {
                rte_exit(EXIT_FAILURE, "Error openning server \'%s\' config\n", kvlb->cfg_filename);
        }
        ret = fscanf(cfg, "%*s %d", &temp);
        if (temp <= 0) {
                rte_exit(EXIT_FAILURE, "Error parsing config, need at least one server configurations\n");
        }
        kvlb->number_of_server = temp;

        kvlb->server = (struct server *)rte_malloc("backend server info", sizeof(struct server) * kvlb->number_of_server, 0);
        if (kvlb->server == NULL) {
                rte_exit(EXIT_FAILURE, "Malloc failed, can't allocate server information\n");
        }

        for (i = 0; i < kvlb->number_of_server; i++) {
                ret = fscanf(cfg, "%s %s", ip, mac);
                if (ret != 2) {
                        rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
                }

                ret = onvm_pkt_parse_ip(ip, &kvlb->server[i].server_ip);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config IP address #%d\n", i);
                }

                ret =onvm_pkt_parse_mac(mac, kvlb->server[i].server_addr_bytes);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config MAC address #%d\n", i);
                }
        }

        fclose(cfg);
        printf("\nARP config:\n");
        for (i = 0; i < kvlb->number_of_server; i++) {
                printf("%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 " ", 
                        kvlb->server[i].server_ip & 0xFF, (kvlb->server[i].server_ip >> 8) & 0xFF, (kvlb->server[i].server_ip >> 16) & 0xFF, (kvlb->server[i].server_ip >> 24) & 0xFF);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                        kvlb->server[i].server_addr_bytes[0], kvlb->server[i].server_addr_bytes[1],
                        kvlb->server[i].server_addr_bytes[2], kvlb->server[i].server_addr_bytes[3],
                        kvlb->server[i].server_addr_bytes[4], kvlb->server[i].server_addr_bytes[5]);
        }

        return ret;
}


/*
 * Parse and assign load balancer server/client interface information
 */
static void
get_iface_inf(void) {
        int fd, i;
        struct ifreq ifr;
        uint8_t client_addr_bytes[ETHER_ADDR_LEN];
        uint8_t server_addr_bytes[ETHER_ADDR_LEN];

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        ifr.ifr_addr.sa_family = AF_INET;

        /* Parse server interface */
        strncpy(ifr.ifr_name, kvlb->server_iface_name, IFNAMSIZ-1);

        ioctl(fd, SIOCGIFADDR, &ifr);
        kvlb->ip_kvlb_server  = *(uint32_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

        ioctl(fd, SIOCGIFHWADDR, &ifr);
        for (i = 0; i < ETHER_ADDR_LEN; i++)
                server_addr_bytes[i] = ifr.ifr_hwaddr.sa_data[i];

        /* Parse client interface */
        strncpy(ifr.ifr_name, kvlb->client_iface_name, IFNAMSIZ-1);

        ioctl(fd, SIOCGIFADDR, &ifr);
        kvlb->ip_kvlb_client  = *(uint32_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

        ioctl(fd, SIOCGIFHWADDR, &ifr);
        for (i = 0; i < ETHER_ADDR_LEN; i++)
                client_addr_bytes[i] = ifr.ifr_hwaddr.sa_data[i];

        /* Compare the interfaces to onvm_mgr ports by hwaddr and assign port id accordingly */
        if (memcmp(&client_addr_bytes, &ports->mac[0], ETHER_ADDR_LEN) == 0) {
                kvlb->port_client = ports->id[0];
                kvlb->port_server = ports->id[1];
        } else {
                kvlb->port_client = ports->id[1];
                kvlb->port_server = ports->id[0];
        }

        close(fd);

        printf("\nLoad balancer interfaces:\n");
        printf("Client iface \'%s\' ID: %d, IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                kvlb->client_iface_name, kvlb->port_client, kvlb->ip_kvlb_client,
                kvlb->ip_kvlb_client & 0xFF, (kvlb->ip_kvlb_client >> 8) & 0xFF, (kvlb->ip_kvlb_client >> 16) & 0xFF, (kvlb->ip_kvlb_client >> 24) & 0xFF);
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        client_addr_bytes[0], client_addr_bytes[1],
                        client_addr_bytes[2], client_addr_bytes[3],
                        client_addr_bytes[4], client_addr_bytes[5]);
        printf("Server iface \'%s\' ID: %d, IP: %" PRIu32 " (%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "), ",
                kvlb->server_iface_name, kvlb->port_server, kvlb->ip_kvlb_server,
                kvlb->ip_kvlb_server & 0xFF, (kvlb->ip_kvlb_server >> 8) & 0xFF, (kvlb->ip_kvlb_server >> 16) & 0xFF, (kvlb->ip_kvlb_server >> 24) & 0xFF);
        printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        server_addr_bytes[0], server_addr_bytes[1],
                        server_addr_bytes[2], server_addr_bytes[3],
                        server_addr_bytes[4], server_addr_bytes[5]);
}


/**************************************************/
/*********** packet handler related ***************/
/**************************************************/
static int update_flow_isactive(uint64_t elapsed_cycles,struct flow_info *data);
static int ft_clear(void);
static int ft_add(struct onvm_ft_ipv4_5tuple* key, struct flow_info **flow);
static int ft_lookup(struct rte_mbuf* pkt, struct flow_info **flow);
hotkey* parse_mc_key(struct rte_mbuf* pkt, int offset);
static int hotkey_freq_decrease(void);
static int hotkey_output(void);
static int hotkey_lookup(char *k, char *v);
static int hotkey_detector(struct hotkey* hk);
static int cache_lookup(char* key);
static int send_cached_data;
static int nohk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, struct hotkey* hk, struct* ether_hdr ether);
static int hk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, struct hotkey* hk, struct ether_hdr* ether);


/* update if flow is active */
static int
update_flow_isactive(uint64_t elapsed_cycles,struct flow_info *data){

        if (unlikely(data == NULL)) {
                return -1;
        }

        // if timeout, set data as not active
        if ((elapsed_cycles - data->last_pkt_cycles) / rte_get_timer_hz() >= kvlb->expire_time) {
                data->is_active = 0;
        } else {
                data->is_active = 1;
        }

        return 0;
}


/* clear flow talbe */
static int
ft_clear(void){
        struct flow_info *data = NULL;
        struct onvm_ft_ipv4_5tuple *key = NULL;
        uint32_t next = 0;
        int ret = 0;

        printf("Clearing expired entries\n");

        //kvlb
        if (unlikely(kvlb == NULL)) {
                return -1;
        }

        while(onvm_ft_iterate(kvlb->ft, (const void **)&key, (void **)&data, &next) > -1){
                ret = update_flow_isactive(kvlb->elapsed_cycles, data);
                if (ret < 0) {
                        return -1;
                }

                if (!data->is_active) {
                        ret = onvm_ft_remove_key(kvlb->ft, key);
                        kvlb->num_stored--;
                        if (ret < 0) {
                                printf("Key should have been removed, but was not\n");
                                kvlb->num_stored++;
                        }
                }
        }

        return 0;
}


/* add an entry to flow table */
static int
ft_add(struct onvm_ft_ipv4_5tuple* key, struct flow_info **flow){
        struct flow_info *data = NULL;

        if (unlikely(key == NULL || kvlb == NULL)) {
                return -1;
        }

        // table avaiable, if full then clean
        if (FLOW_TABLE_SIZE - kvlb->num_stored - 1 == 0) {
                int ret = ft_clear();
                if (ret < 0) {
                        return -1;
                }
        }
        // append entry
        int ft_index = onvm_ft_add_key(kvlb->ft, key, (char **)&data);
        if (ft_index < 0) {
                return -1;
        }
        // change proporty accordingly
        kvlb->num_stored++;

        data->dest = kvlb->num_stored % kvlb->number_of_server;
        data->last_pkt_cycles = kvlb->elapsed_cycles;
        data->is_active = 0;

        *flow = data;
        return 0;
}


/* lookup flow table */
static int
ft_lookup(struct rte_mbuf* pkt, struct flow_info **flow){
        struct flow_info *data = NULL;
        struct onvm_ft_ipv4_5tuple key;

        if (unlikely(pkt == NULL || kvlb == NULL || flow == NULL)) {
                return -1;
        }

        int ret = onvm_ft_fill_key_symmetric(&key, pkt);
        if (ret < 0) {
            return -1;
        }

        int ft_index = onvm_ft_lookup_key(kvlb->ft, &key, (char **)&data); //this api hashes
        if (ft_index == -ENOENT) {
            return ft_add(&key, flow);
        }
        else if(ft_index < 0) {
            printf("Error occurred with packet hashing");
            return -1;
        }
        else {
            data->last_pkt_cycles = kvlb->elapsed_cycles;
            *flow = data;
            return 0;
        }
}


/* parse memcached data from packet */
hotkey* parse_mc_key(struct rte_mbuf* pkt, int offset){
        struct hotkey *hk;

        char *data;

        // get kv pair from pkt with offset of ether_hdr + ip_hdr + udp_hdr
        data = (char *)rte_pktmbuff_mtod_offset(pkt, char *, offset);

        strncpy(hk->mc_key, data, MCKEY_LEN);
        
        if (strlen(data) > MCKEY_LEN) {
                strcpy(hk->mc_value, &data[MCKEY_LEN + 1]);
        }
        
        hk->lossy_counter = -1;

        return hk;
}


/* decrease counter when reach window boudary */
static int
hotkey_freq_decrease(void){
        int i;
        // interate all hot key in hotkey table, decrease each by 1
        // drop the hotkey if lossy_counter reaches 1
        for(i = 0; i < hkt->num_stored; i++)
        {
                hkt->hks[i]->lossy_counter --;
                if (hkt->hks[i]->lossy_counter == 1) {
                    hkt_delete(hkt, hkt->hks[i]->mc_key);
                }
        }
        return 0;
}


/* output the hotkey table to local cache, and reset all counter */
static int
hotkey_output(void){
        int threshold = 0;

        // compute hotkey for first time 
        if (hkt->is_ht_detected == 0 && cache->count == 0) {
                if (cache == NULL) {
                    printf("error occur when create local cache");
                    return -1;
                }
        // later 
        } else {
                cache = cache_clear(cache);
                if (cache == NULL) {
                    printf("error occur when clear local cache");
                    return -1;
                }
        }

        // calculate lossy counting threshold
        threshold = (hkt->frequency - hkt->error) * hkt->num_stored;

        // 
        hkt_filter_above_threshold(hkt, threshold);

        if (cache->kvs[0] != NULL) {
                /* code */
        }

        // start next round of lossy counting 
        hkt->num_stored = 0;
        hkt->elapsed_couter = 0;

        return 0;
}


/* look hotkey in hotkey table */
static int
hotkey_lookup(char *k, char *v){
        int index = 0;

        if (unlikely(k[0] == '\0' || v[0] == '\0')) {
            return -1;
        }

        index = hkt_getindex(hkt, k);
        // cannot find -- new key
        if ( index == -1 ) {
                hkt_insert(hkt, k, "\0");
        // find a key without value, then we assign it
        } else if( index != -1 || hkt->hks[index]->mc_value[0] == '\0' || v[0] != '\0' ) { 
                strcpy(hkt->hks[index]->mc_value, v);
                hkt->hks[index]->lossy_counter ++;
        } else {
                hkt->hks[index]->lossy_counter ++;
        }

        return 0;
}


static int
hotkey_detector(struct hotkey* hk){
        int ret;

        // lossy counting
        hkt->elapsed_couter ++;
        if (hkt->elapsed_couter > hkt->lossy_window_size) {
                hotkey_freq_decrease();
                hkt->elapsed_couter = 0;
                hkt->elapsed_window ++;
                if ((hkt->elapsed_window * hkt->lossy_window_size) + 1 > hkt->ht_table_size) {
                    hotkey_output();
                }
        }

        // look up given hot key, if not found then add
        ret = hotkey_lookup(hk->mc_key, hk->mc_value);
        if (ret == -1) {
                printf("Error occur when lookup the memcached key in hotkey table");
                return -1;
        }

        return 0;
}


/* lookup given key in local cache */
static int
cache_lookup(char* key){
        char *value = NULL;
        int index;

        if (unlikely(key[0] == '\0')) {
            return -1;
        }

        value = realloc(cache_search(cache, key), );
        //TODO:
        index = cache_getindex(cache, key);
        // not found in cache
        if ( value == NULL ) {
                return 2;
        } else {
                strcpy(c_kv->mc_key, key);
                strcpy(c_kv->mc_value, value);
                hkt->hks[index]->lossy_counter ++;
        }

        return 0;
}


static int
send_cached_data(struct hotkey* hk,  int type){
        int send_data_socket;
        struct sockaddr_in des_addr;
        socklen_t addr_size;

        char *value;
        char *data;
        
        // search key in cache or in hk_table 
        if (type == 1) {
                // cache hit
                value = cache_search(cache, hk->mc_key);
        } else {
                // hotkey table hit 
                value = hkt_search(hkt, hk->mc_key);
        }

        // check if get value correctly
        if (value[0] == '\0' || value == NULL) {
                printf("error occur when search stored kv");
                return -1;
        }
        
        // concartenate final data
        //TODO:
        data = strncat(data, hk->mc_key, MCKEY_LEN);
        data = strncat(data, value, MCVALUE_LEN);

        // addr stuff
        des_addr.sin_family = AF_INET;
        des_addr.sin_port = htons(11212);
        des_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
        addr_size = sizeof(des_addr);

        // create udp socket 
        send_data_socket = socket(PF_INET, SOCK_DGRAM, 0);

        // send hotkey back to client, then close
        sendto(send_data_socket, data, MCKEY_LEN + MCVALUE_LEN, 0, (struct sockaddr*)&des_addr, addr_size);
        close(send_data_socket);

        return 0;
}


/* handle packet before hotkey table generated */
static int
nohk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, struct hotkey* hk, struct* ether_hdr ether) {
        int ret;
        int i;

        ret = ft_lookup(pkt, &flow_info);
        if (ret == -1) {
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
        }

        hkt->elapsed_couter = 0;
        ret = hotkey_detector(hk);
        if (ret == -1) {
                printf("error occur when lossy counting");
                return -1;
        }

        // send data directly server if found in hotkey table
        send_cached_data(hk, 2);
        // new packet, save its info
        if (flow_info->is_active == 0) {
                flow_info->is_active = 1;
                for(i = 0; i < ETHER_ADDR_LEN; i++)
                {
                        flow_info->source_addr_bytes[i] = ether->source_addr_bytes;
                }
        }

        // packet from server
        if (pkt->port == kvlb->port_server) {
                rte_eth_macaddr_get(kvlb->port_server, &ether->s_addr);
                for(i = 0; i < ETHER_ADDR_LEN; i++)
                {
                        ether->d_addr.addr_bytes[i] = flow_info->source_addr_bytes[i];
                }

                ip->src_addr = kvlb->ip_kvlb_client;
                meta->destination = kvlb->port_client;
        } else { //packet from client
                rte_eth_macaddr_get(kvlb->port_server, &ether->s_addr);

                for(int i = 0; i < ETHER_ADDR_LEN; i++)
                {
                        ether->d_addr.addr_bytes[i] = kvlb->server[flow_info->dest].server_addr_bytes[i];
                }

                ip->dst_addr = kvlb->server[flow_info->dest].server_ip;
                meta->destination = kvlb->port_server;
        }

        // recalculate checksum
        onvm_pkt_set_checksum(pkt);

        meta->action = ONVM_NF_ACTION_OUT;
}


/* handle packet after a hotkey table generated and have loacl cache */
static int
hk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, struct hotkey* hk, struct ether_hdr* ether) {
        int ret = 0;

        if (hkt->is_ht_detected == 1) {
                ret = cache_lookup(hk->mc_key); 
                if (ret == -1) {
                        printf("error looking up cached hot key-value");
                        return -1;
                // local cache miss
                } else if(ret == 2 ){
                        nohk_packet_handler(pkt, meta, flow_info, hk, ether);
                } else {
                        if (c_kv->mc_key[0] == '\0' || c_kv->mc_value[0] == '\0' ) {
                                printf("Error occur when search cached kv");
                                return -1;
                        }

                        // send data back to client from cache using udp socket
                        send_cached_data(hk, 1);
                }
        // error
        } else { 
                printf("Tried to search cache without existing cache");
                return -1;
        }

        return 0;
}


/**************************************************/
/************** ONVM related function *************/
/**************************************************/
/* calledback every attempted  */
static int
callback_handler(__attribute__((unused)) struct onvm_nf_info *nf_info) {
        kvlb->elapsed_cycles = rte_get_tsc_cycles();

        if ((kvlb->elapsed_cycles - kvlb->last_cycles) / rte_get_timer_hz() > kvlb->expire_time) {
                kvlb->last_cycles = kvlb->elapsed_cycles;
        }

        return 0;
}


/* handle every packet passed to NF */
static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {

        static uint32_t counter = 0;
        struct udp_hdr *udp;
        struct ipv4_hdr *ip;
        struct ether_hdr *ether;
        struct flow_info *flow_info;

        struct hotkey *hk;
        int data_offset = 0;

        ether = onvm_pkt_ether_hdr(pkt);
        ip = onvm_pkt_ipv4_hdr(pkt);
        udp = onvm_pkt_udp_hdr(pkt);

        // drop invalid packet
        if (ether == NULL || ip->src_addr == 0 || ip->dst_addr == 0 || udp == NULL) {
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }

        if (pkt->port == kvlb->port_client) {
                ip->dst_addr = 0;
        } else {
                ip->src_addr = 0;
        }

        // parse memcached data from packet
        data_offset = sizeof(ether_hdr) + sizeof(ipv4_hdr) + sizeof(udp_hdr);
        hk = *parse_mc_key(pkt, data_offset);
        if (strcmp(hk->mc_key, "") == 0) {
                printf("error occur when parse memcached key from packet");
                return -1;
        }

        // process packet based on if hotkey detected
        if (hkt->is_ht_detected == 0) {
            nohk_packet_handler(pkt, meta, flow_info, hk, ether);
        } else {
            hk_packet_handler(pkt, meta, flow_info, hk, ether);
        }

        if(++counter == print_delay){
            do_stats_display(pkt);
            print_flow_info(flow_info);
            counter = 0;
        }

        return 0;
}



/**************************************************/
/******************* main func ********************/
/**************************************************/
int main(int argc, char *argv[]) {
        int arg_offset;
        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        kvlb = rte_calloc("state", 1, sizeof(struct kvloadbalancer), 0);

        if (kvlb == NULL) {
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Unable to initialize NF kvlb struct");
        }

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        kvlb->ft = onvm_ft_create(FLOW_TABLE_SIZE, sizeof(struct flow_info));
        if (kvlb->ft == NULL) {
                onvm_nflib_stop(nf_info);
                rte_exit(EXIT_FAILURE, "Unable to create flow table");
        }

        get_iface_inf();
        parse_backend_config();

        cache = cache_init();
        hkt = hk_table_init();

        hkt->is_ht_detected = 0;
        hkt->lossy_total = 1000;
        hkt->frequency = 0.2;
        hkt->error = 0.1 * hkt->frequency;

        kvlb->expire_time = 32;
        kvlb->elapsed_cycles = rte_get_tsc_cycles();

        onvm_nflib_run_callback(nf_info, &packet_handler, &callback_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
