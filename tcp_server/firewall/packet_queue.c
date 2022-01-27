#include "packet_queue.h"
#include <string.h>

void pq_insert(PacketQueue *pq, Conn_signature_t *sig) {
    free(pq->flows[pq->pos].iphdr);
    free(pq->flows[pq->pos].tcphdr);
	pq->flows[pq->pos++] = *sig;
	pq->pos %= TAM;
    pq->is_initialized = true;
    pq->size++;
}

void pq_erase(PacketQueue *pq) {
	memset(&pq->flows, 0, TAM * sizeof(Conn_signature_t));
	pq->pos = 0;
}

bool pq_is_full(PacketQueue *pq) {
    if (pq->size == TAM) return true;
    return false;
}
