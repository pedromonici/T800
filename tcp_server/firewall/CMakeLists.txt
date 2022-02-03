idf_component_register(SRCS "firewall.c" "stateless.c" "statefull.c" "connection.c" "model.cc" "main_functions.cc" "queue.c"
                    PRIV_REQUIRES tflite-lib spi_flash
                    INCLUDE_DIRS "include")
