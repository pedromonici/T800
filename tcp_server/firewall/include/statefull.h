#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "esp_err.h"
#include "connection_id.h"

void set_statefull_model(err_t (*_statefull_fn)(Conn_id_t, Conn_signature_t));

#ifdef __cplusplus
}
#endif
