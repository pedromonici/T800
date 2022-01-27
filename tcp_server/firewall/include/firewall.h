#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CONNECTIONS 11
#define MAX_QUARANTINE_SIZE 4

#include "statefull.h"
#include "stateless.h"
#include "connection.h"

typedef enum _firewall_mode {
    STATELESS,
    STATEFULL
} firewall_mode;

typedef struct _firewall_config_t {
    err_t (*stateless_eval)(struct pbuf*);
    err_t (*statefull_eval)(conn_id_t, queue<conn_headers_t>);
    firewall_mode mode;
} firewall_config_t;

void init_firewall(firewall_config_t cfg);

err_t run_firewall(struct pbuf* p);

#ifdef __cplusplus
}
#endif
