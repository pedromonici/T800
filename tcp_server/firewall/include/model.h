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

err_t validate_packet(struct pbuf *p, Conn_id_t id, Conn_signature_t signature);

#ifdef __cplusplus
}
#endif

#endif
