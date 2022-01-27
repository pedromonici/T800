#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "esp_log.h"

err_t decision_tree_depth_6(struct pbuf *p);

err_t decision_tree_depth_7(struct pbuf *p);

err_t decision_tree_depth_8(struct pbuf *p);

err_t decision_tree_depth_9(struct pbuf *p);

err_t decision_tree_depth_10(struct pbuf *p);

err_t decision_tree_depth_11(struct pbuf *p);

err_t decision_tree_depth_12(struct pbuf *p);


#ifdef __cplusplus
}
#endif
