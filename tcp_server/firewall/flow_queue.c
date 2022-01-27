#include "flow_queue.h"

void fq_insert(FlowQueue *fq, Conn_signature_t *sig) {
    pq_erase(&fq->pq[fq->end]);
    pq_insert(&fq->pq[fq->end], sig);

    fq->end = (fq->end + 1) % TAM_FLOW;

    int prev = fq->end - 1 < 0 ? TAM_FLOW - 1 : fq->end - 1;

    if (prev == fq->start) {
        fq->start = (fq->start + 1) % TAM_FLOW;
    }
}

PacketQueue *fq_get_flow(FlowQueue *fq, int index) {
    return &fq->pq[index];
}

bool fq_is_full(FlowQueue *fq) {
    if (fq->end >= fq->start) return (fq->end - fq->start == TAM_FLOW);
    return (TAM_FLOW - fq->start + fq->end == TAM_FLOW);
}
