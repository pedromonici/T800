#pragma once

#define MAX_CONNECTIONS 11
#define MAX_QUARANTINE_SIZE 4

#include "statefull.h"
#include "stateless.h"
#include "connection.h"
#include "hash.h"
#include "queue.h"

typedef enum _firewall_mode {
    UNINITIALIZED,
    STATELESS,
    STATEFULL
} firewall_mode;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _firewall_config_t {
    err_t (*stateless_eval)(struct ip_hdr *, struct tcp_hdr *);
    err_t (*statefull_eval)(queue_t *);
    firewall_mode mode;
} firewall_config_t;

void init_firewall(firewall_config_t cfg);

err_t run_firewall(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr);

#ifdef __cplusplus
}
#endif
