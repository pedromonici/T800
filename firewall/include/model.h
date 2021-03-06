#ifndef TENSORFLOW_LITE_MICRO_EXAMPLES_HELLO_WORLD_MODEL_H_
#define TENSORFLOW_LITE_MICRO_EXAMPLES_HELLO_WORLD_MODEL_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned char g_model[];
extern const unsigned int g_model_len;

#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "esp_log.h"
#include "connection.h"
#include "queue.h"

err_t validate_packet(queue_t *q);

#ifdef __cplusplus
}
#endif

#endif
