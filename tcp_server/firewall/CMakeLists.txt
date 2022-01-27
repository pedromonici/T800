idf_component_register(SRCS "firewall.c" "flow_queue.c" "packet_queue.c" "model.cc" "main_functions.cc"
                    PRIV_REQUIRES tflite-lib spi_flash
                    INCLUDE_DIRS "include")
