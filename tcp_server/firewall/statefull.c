#include "statefull.h"

err_t (*statefull_fn)(Conn_id_t, Conn_signature_t);

void set_statefull_model(err_t (*_statefull_fn)(Conn_id_t, Conn_signature_t)) {
    statefull_fn = _statefull_fn;
}
