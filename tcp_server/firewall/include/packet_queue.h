#ifndef _PACKET_QUEUE_H_
#define _PACKET_QUEUE_H_

#include "lwip/pbuf.h"
#include "lwip/connection_id.h"

#define TAM 4

// TODO: rename to `Signature_Queue` ?
typedef struct _packet_queue{
	Conn_signature_t flows[TAM];
	u8_t pos;
    bool is_initialized;
    u32_t size;
} PacketQueue;

void pq_insert(PacketQueue *pq, Conn_signature_t *id);
void pq_erase(PacketQueue *pq);
bool pq_is_full(PacketQueue *pq);

#endif
