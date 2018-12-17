/*********************************************************************
 * kv_loadbalancer.c - kvlb NF for research project.
 *
 * A. before hotkey table generated:
 *      1. drop non-udp packet
 *      2. set kvlb'ip to server or client repesctly
 *      3. get packet flow entry
 *          - if new, save
 *          - if old, send based on rule table
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

#define NF_TAG "kvloadbalancer"

/* table size */
# FLOW_TABLE_SIZE 65536
# HOTKEY_TABLE_SIZE 
# MCKEY_LEN 250 //max key length in Memcached is 250 character
# MCVALUE_LEN  //TODO: 明天和小胖商量决定

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

struct ht_table
{
        uint16_t ht_table_size;
        uint16_t num_stored;

        // hot keys
        struct hotkey *hk;

        // window size and stream counter
        uint16_t lossy_window;
        uint16_t elapsed_couter;
        int elapsed_window;

        // lossy counting threshold
        float frequency;
        float error;

        int is_ht_detected;
}

struct hotkey
{
        //memcached kv
        char mc_key[MCKEY_LEN];
        char mc_value[MCVALUE_LEN];

        unsigned int lossy_counter;

};

// associative array struct
struct hotkey_cache
{
        char mc_key[MCKEY_LEN];
        char mc_value[MCVALUE_LEN];
};

/* struct declear */
struct onvm_nf_info *nf_info; // struct for information about this NF
struct kvloadbalancer *kvlb;
struct hk_table *hkt;
struct hotkey_cache *cache;

extern struct prot_info *ports;

/* varibles declear */
static uint32_t print_delay = 1000000; // number of package between each print



/*********** main func related function ***********/
/*
 * Parse the application arguments.
 *  TODO: modify accordingly
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        kvlb->cfg_filename = NULL;
        kvlb->client_iface_name = NULL;
        kvlb->server_iface_name = NULL;
        hkt->lossy_window = NULL;

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
                        hkt->lossy_window = strdup(optarg);
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
        printf("N°   : %"PRIu64"\n", pkt_process);
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
 * and fills up the backend_server array. This includes the mac and ip 
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
        kvlb->server_count = temp;

        kvlb->server = (struct backend_server *)rte_malloc("backend server info", sizeof(struct backend_server) * kvlb->server_count, 0);
        if (kvlb->server == NULL) {
                rte_exit(EXIT_FAILURE, "Malloc failed, can't allocate server information\n");
        }

        for (i = 0; i < kvlb->server_count; i++) {
                ret = fscanf(cfg, "%s %s", ip, mac);
                if (ret != 2) {
                        rte_exit(EXIT_FAILURE, "Invalid backend config structure\n");
                }

                ret = onvm_pkt_parse_ip(ip, &kvlb->server[i].d_ip);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config IP address #%d\n", i);
                }

                ret =onvm_pkt_parse_mac(mac, kvlb->server[i].d_addr_bytes);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Error parsing config MAC address #%d\n", i);
                }
        }

        fclose(cfg);
        printf("\nARP config:\n");
        for (i = 0; i < kvlb->server_count; i++) {
                printf("%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 " ", 
                        kvlb->server[i].d_ip & 0xFF, (kvlb->server[i].d_ip >> 8) & 0xFF, (kvlb->server[i].d_ip >> 16) & 0xFF, (kvlb->server[i].d_ip >> 24) & 0xFF);
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                        kvlb->server[i].d_addr_bytes[0], kvlb->server[i].d_addr_bytes[1],
                        kvlb->server[i].d_addr_bytes[2], kvlb->server[i].d_addr_bytes[3],
                        kvlb->server[i].d_addr_bytes[4], kvlb->server[i].d_addr_bytes[5]);
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




/*********** data struct implementation ***********/
//TODO: dynamic hot key structure implementation
/* init hotkey table as a dynamic array */
static int
hkt_init()

static int
hkt_append()

static int
hkt_delete()

static int
hkt_clear()

static int
hkt_is_empty()

//TODO: local cache structure implementation
static int
cache_init()

static int
cache_add()

static int
cache_clear()

static int
cache_is_empty()


/*********** packet handler related ***********/
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
ft_add(struct onvm_nf_ipv4_5tuple* key, struct flow_info **flow){
        struct flow_info *data = NULL;

        if (unlikely(key == NULL || kvlb == NULL)) {
                return -1;
        }

        // table avaiable, if full then clean
        if (TABLE_SIZE - kvlb->num_stored - 1 == 0) {
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

/* handle packet before hotkey table generated */
static int
nohk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, int data_offset) {
        
        if (pkt->port == kvlb->port_client) {
                ip->dst_addr = 0;
        } else {
                ip->src_addr = 0;
        }

        int ret = ft_lookup(pkt, &flow_info);
        if (ret == -1) {
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
        }

        hkt->elapsed_couter = 0;
        hkt->last_couter = 0;
        ret = hotkeydetector(pkt, data_offset);
        if (ret == -1) {
                printf("error occur when detector");
        }

        // new packet, save its info
        if (flow_info->is_active == 0) {
                flow_info->is_active == 1;
                for(int i = 0; i < ETHER_ADDR_LEN; i++)
                {
                        flow_info->source_addr_bytes[i] = ether->source_addr_bytes
                }
        }

        // packet from server
        if (pkt->port == kvlb->port_server) {
                rte_eth_macaddr_get(kvlb->port_server, &ether->s_addr);
                for(int i = 0; i < ETHER_ADDR_LEN; i++)
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

/* append hotkey to hotkey table */
static int
hotkey_add(char *k, char *v){
        struct hotkey *hk;
        int ret = 0;

        hk->mc_key = k;
        hk->mc_value = v;
        hk->lossy_counter = 0;

        //TODO: 取决于最后的数据结构
        ret = hkt_append(hk);
        if (ret == -1) {
            retrun -1;
        }

        hkt->num_stored ++;
        hkt->hk[num_stored - 1]->lossy_counter = 1;
}


/* look hotkey in hotkey table */
static int
hotkey_lookup(char *k, char *v){
        int ret = 0;

        if (unlikely(k == NULL)) {
            return -1;
        }
        
        //TODO:遍历现有的hotkey table
        hk_index = 
        if ( hk_index == -1 ) {
            ret = hotkey_add(k, v);

            if (ret == -1) {
                printf("error occur when add the memcached key to hotkey table");
                return -1;
            }
        } else {
            hkt->hk[hk_index]->lossy_counter ++;
        }

        return 0;
}


/* decrease counter when reach window boudary */
void
hotkey_freq_decrease(){
        
        // interate all hot key in hotkey table, decrease each by 1
        // drop the hotkey if lossy_counter reaches 1
        for(uint16_t i = 0; i < hkt->num_stored; i++)
        {
                hkt->ht[i]->lossy_counter --;
                if (hkt->ht[i]->lossy_counter == 1) {
                    hkt_delete(hkt->ht[i]);
                }
        }
}


/* output the hotkey table to local cache, and reset all counter */
static int
hotkey_output(){
        int thershold = 0;
        int ret = 0;

        // prepare local cache
        // compute hotkey for first time 
        if (hkt->is_ht_detected == 0 && hkt->num_stored == 0) {
                ret = cache_init();
                if (ret == -1) {
                    printf("error occur when create local cache");
                    return -1;
                }
        } else { // later
                cache_clear();
                ret = cache_is_empty();
                if (ret == -1) {
                    printf("error occur when clear local cache");
                    return -1;
                }
        }

        // calculate lossy counting thershold
        thershold = (hkt->frequency - hkt->error) * hkt->num_stored

        // iterate hotkey table, 
        for(uint16_t i = 0; i < hkt->num_stored; i++)
        {
                if(hkt->[i]->lossy_counter > thershold){
                        //TODO:
                        cache_append();
                }
                hkt_delete();
        }

        hkt->num_stored = 0;
        hkt->elapsed_couter = 0;

        //TODO: hotkey table是否空了
        if (/* condition */) {
            /* code */
        }
        
}


static int
hotkey_detector(struct rte_mbuf* pkt, int offset){
        char k[MCKEY_LEN];
        char v[MCVALUE_LEN];
        char data[MCKEY_LEN + MCVALUE_LEN];
        int ret;

        if(unlikely(pkt == NULL || offset == 0)){
            return -1;
        }

        // get kv pair from pkt with offset of ether_hdr + ip_hdr + udp_hdr
        data = (char *)rte_pktmbuff_mtod_offset(pkt, u_char *, offset);
        for(int i = 0; i < MCKEY_LEN; i++)
        {
                k[i] = data[i];
        }
        for(int i = 0; i < MCVALUE_LEN; i++)
        {
                v[i] = data[MCKEY_LEN + i];
        }

        // lossy counting
        hkt->elapsed_couter ++;
        if (hkt->elapsed_couter > hkt->lossy_window) {
                hotkey_freq_decrease();
                hkt->elapsed_couter = 0;
                hkt->elapsed_window ++;
                if ((hkt->elapsed_window * hkt->lossy_window) + 1 > hkt->ht_table_size) {
                    hotkey_output();
                }
        }

        ret = hotkey_lookup(k, v);
        if (ret == -1) {
                printf("Error occur when lookup the memcached key in hotkey table");
                return -1;
        }

        return 0;
}

//TODO:
/* handle packet after a hotkey table generated and have loacl cache */
static int
hk_packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta, struct flow_info* flow_info, struct udp_hdr* udp) {

}





/*********** ONVM related function ***********/
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

        int data_offset = 0;

        ether = onvm_pkt_ether_hdr(pkt);
        ip = onvm_pkt_ipv4_hdr(pkt);
        udp = onvm_pkt_udp_hdr(pkt);

        if (ether == NULL || ip->src_addr == 0 || ip->dst_addr == 0 || udp == NULL) {
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }

        data_offset = sizeof(ether_hdr) + sizeof(ipv4_hdr) + sizeof(udp_hdr);

        if (hkt->is_ht_detected == 0) {
            nohk_packet_handler(pkt, meta, flow_info, data_offset);
        } else {
            hk_packet_handler();
        }

        if(++counter == print_delay){
            do_stats_display(pkt);
            print_flow_info(flow_info);
            counter = 0;
        }

        return 0;
}





/*********** main func ***********/
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

        hkt->is_ht_detected = 0;
        hkt->lossy_total = 1000;
        hkt->frequency = 0.2;
        hkt->error = 0.1 * hkt->frequency;

        kvlb->expire_time = 32;
        kvlb->elapsed_cycles = rte_get_tsc_cycles();

        onvm_nflib_run_callback(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
