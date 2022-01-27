#include "lwip/connection_id.h"

void firewall_get_key_from_id(Conn_id_t id, u8_t *key) {
    size_t offset = 0;
    memcpy(key+offset,    &id.ip_src,   sizeof(ip4_addr_p_t));
    offset += sizeof(ip4_addr_p_t);
    memcpy(key+offset,    &id.ip_dst,   sizeof(ip4_addr_p_t));
    offset += sizeof(ip4_addr_p_t);
    memcpy(key+offset,    &id.port_src, sizeof(u16_t));
    offset += sizeof(u16_t);
    memcpy(key+offset,    &id.port_dst, sizeof(u16_t));
}

bool firewall_id_cmp(Conn_id_t* id1, Conn_id_t* id2) {
    return  id1->ip_src.addr == id2->ip_src.addr &&
            id1->ip_dst.addr == id2->ip_dst.addr &&
            id1->port_src == id2->port_src &&
            id1->port_dst == id2->port_dst;
}

bool firewall_signature_cmp(Conn_signature_t* sig1, Conn_signature_t* sig2) {
    Conn_id_t id1 = {
        .ip_src = sig1->iphdr->src,
        .ip_dst = sig1->iphdr->dest,
        .port_src = sig1->tcphdr->src,
        .port_dst = sig1->tcphdr->dest,
    };
    Conn_id_t id2 = {
        .ip_src = sig2->iphdr->src,
        .ip_dst = sig2->iphdr->dest,
        .port_src = sig2->tcphdr->src,
        .port_dst = sig2->tcphdr->dest,
    };

    return firewall_id_cmp(&id1, &id2);
}
