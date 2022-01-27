#ifndef _CONN_ID_H_
#define _CONN_ID_H_

#include "lwip/opt.h"

#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/ip4_addr.h"
#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _conn_id_t {
  ip4_addr_p_t ip_src;
  ip4_addr_p_t ip_dst;
  u16_t port_src;
  u16_t port_dst;
} Conn_id_t;

typedef struct _conn_signature_t {
  struct ip_hdr *iphdr;
  struct tcp_hdr *tcphdr;
} Conn_signature_t;

void firewall_get_key_from_id(Conn_id_t id, u8_t *key);
bool firewall_id_cmp(Conn_id_t* id1, Conn_id_t* id2);

// Compare both the ip_header checksum and the tcp_header checksum of both signatures
bool firewall_signature_cmp(Conn_signature_t* sig1, Conn_signature_t* sig2);

#ifdef __cplusplus
}
#endif

#endif
