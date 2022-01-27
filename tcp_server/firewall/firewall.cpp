#include "firewall.h"
#include "queue"
#include "array"

using std::queue;
using std::array;

static const char *TAG = "Firewall";

typedef struct _flow {
    conn_id_t id;
    queue<conn_headers_t> headers;
    bool is_malicious;

    bool is_initialized() {
        return id.ip_src != 0;
    }

    bool id_matches(conn_id_t* id2) {
        return id_cmp(&id, id2);
    }
} flow_t;

typedef struct _flow_hash {
    array<flow_t, MAX_CONNECTIONS> flows;
    queue<u16_t> history;
} flow_hash_t;

// ======== Firewall structures ========
flow_hash_t flow_hash;
firewall_config_t config;
// =====================================

void init_firewall(firewall_config_t cfg) {
    config = cfg;
    switch (cfg.mode) {
        case STATELESS:
            if (cfg.stateless_eval == NULL) abort();
            stateless_eval = cfg.stateless_eval;
            break;
        case STATEFULL:
            if (cfg.statefull_eval == NULL) abort();
            statefull_eval = cfg.statefull_eval;
            break;
    }
}

err_t run_firewall(struct pbuf* p, struct ip_hdr *iphdr, struct tcp_hdr *tcphdr) {
    switch (config.mode) {
        case STATELESS:
            return config.stateless_eval(p);
        case STATEFULL:
            return firewall_statefull(id, headers);
    }
}

err_t firewall_statefull(struct pbuf* p, struct ip_hdr *iphdr, struct tcp_hdr *tcphdr) {
    Conn_id_t id = {
        .ip_src   = iphdr->src,
        .ip_dst   = iphdr->dest,
        .port_src = tcphdr->src,
        .port_dst = tcphdr->dest
    };
    Conn_headers_t headers;
    headers.iphdr = malloc(sizeof(struct ip_hdr));
    headers.tcphdr = malloc(sizeof(struct tcp_hdr));
    memcpy(headers.iphdr, iphdr, sizeof(struct ip_hdr));
    memcpy(headers.tcphdr, tcphdr, sizeof(struct tcp_hdr));

    u8_t key[12] = {0};
    firewall_get_key_from_id(id, key);
    unsigned hash_key = wyhash32(key, 12, 0xcafebabe);
    u16_t idx = hash_key % MAX_CONNECTIONS;

    /* ESP_LOGE(TAG, "HASH_KEY: %u FLOW_IDX: %d", hash_key, flow_idx); */
    flow_t flow = flow_hash.flows[idx];
    if (flow.id_matches(&id)) {  // Packet already has a flow
        /* ESP_LOGW(TAG, "found existed flow"); */
        // Insert current packet headers
        if (flow.headers.size() == MAX_QUARANTINE_SIZE) {
            conn_headers_t old_headers = flow.headers.front();
            free(old_headers.iphdr);
            free(old_headers.tcphdr);
            flow.headers.pop();
        }
        flow.headers.push(headers);
    } else {  // Packet introduces new flow
        ESP_LOGW(TAG, "insert new flow");
        // Get stale flow and swap it with flow from collision
        u16_t oldest_idx = flow_hash.history.front();
        flow_hash.history.pop();
        flow_t oldest_flow = flow_hash.flows[oldest_idx];

        // swap oldest with the flow from collision
        std::swap(oldest_flow, flow);

        // free oldest flow headers
        for (auto el : flow.headers) {
            free(el.iphdr);
            free(el.tcphdr);
        }
        queue<conn_headers_t> empty;
        std::swap(flow.headers, empty);

        // Now set <previous flow on idx> to <new flow>
        flow.id = id;
        flow.headers.push(headers);
        flow.is_malicious = false;
    }

    if (flow.headers.size() == MAX_QUARANTINE_SIZE) {
        if (flow.is_malicious)
            /* ESP_LOGE(TAG, "flow in blacklist"); */
            return ERR_ABRT;
        } else if (config.statefull_eval(flow.id, flow.headers) == ERR_ABRT) {
            /* ESP_LOGE(TAG, "flow malicious"); */
            flow.is_malicious = true;
            return ERR_ABRT;
        }
    } 

    return ERR_OK;
}
