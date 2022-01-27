#ifndef _FLOW_QUEUE_H
#define _FLOW_QUEUE_H

#include "lwip/pbuf.h"
#include "packet_queue.h"

#define TAM_FLOW 10

typedef struct _flow_queue{
	PacketQueue pq[TAM_FLOW];
	u8_t start;
	u8_t end;
} FlowQueue;

// FlowQueue fq_create(void);
void fq_insert(FlowQueue *fq, Conn_signature_t *sig);
PacketQueue *fq_get_flow(FlowQueue *fq, int index);
bool fq_is_full(FlowQueue *fq);

#endif
