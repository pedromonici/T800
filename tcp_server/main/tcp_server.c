#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"

#include "freertos/semphr.h"
#include "esp_err.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "esp_log.h"
#include "esp_check.h"

// To get decision_tree_firewall
#include "firewall.h"
#include "model.h"

#include <unistd.h>     // For sleep()

#define PORT                        CONFIG_EXAMPLE_PORT
#define KEEPALIVE_IDLE              CONFIG_EXAMPLE_KEEPALIVE_IDLE
#define KEEPALIVE_INTERVAL          CONFIG_EXAMPLE_KEEPALIVE_INTERVAL
#define KEEPALIVE_COUNT             CONFIG_EXAMPLE_KEEPALIVE_COUNT
#define ATTACKER_ADDRESS            "192.168.15.10" // Change this to your IP
#define ATTACKER_PORT               6767
#define ATTACKER_EXP_PORT           6768
#define IPERF_PORT                  5001

static const char *TAG = "UDP Server";

bool is_finish = false;

int iperf_run_tcp_server(struct sockaddr_in *listen_addr)
{
    struct sockaddr_in listen_addr4 = { 0 };
    int listen_socket = -1;
    int client_socket = -1;
    int opt = 1;
    int err = 0;
    esp_err_t ret = ESP_OK;
    struct sockaddr_in remote_addr;
    struct timeval timeout = { 0 };

    listen_addr4.sin_family = AF_INET;
    listen_addr4.sin_port = htons(IPERF_PORT);
    listen_addr4.sin_addr.s_addr = 0;
    inet_pton(AF_INET, "192.168.15.20", &(listen_addr4.sin_addr));

    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    ESP_GOTO_ON_FALSE((listen_socket >= 0), ESP_FAIL, exit, TAG, "Unable to create socket: errno %d", errno);

    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    ESP_LOGI(TAG, "Socket created iperf");

    err = bind(listen_socket, (struct sockaddr *)&listen_addr4, sizeof(struct sockaddr_in));
    ESP_GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Socket unable to bind: errno %d, IPPROTO: %d", errno, AF_INET);
    
    ESP_LOGI(TAG, "esperando o accept");
    err = listen(listen_socket, 5);
    ESP_GOTO_ON_FALSE((err == 0), ESP_FAIL, exit, TAG, "Error occurred during listen: errno %d", errno);

    socklen_t len = sizeof(remote_addr);
    client_socket = accept(listen_socket, (struct sockaddr *)&remote_addr, &len);
    ESP_GOTO_ON_FALSE((client_socket >= 0), ESP_FAIL, exit, TAG, "Unable to accept connection: errno %d", errno);
    ESP_LOGW(TAG, "accept: %s,%d\n", inet_ntoa(remote_addr.sin_addr), htons(remote_addr.sin_port));

    timeout.tv_sec = 10;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    memcpy(listen_addr, &listen_addr4, sizeof(struct sockaddr_in));

exit:
    return client_socket;
}

void init(int message_socket) {
    // 1. Signal experiment start to attacker by sending "start"
    struct sockaddr_in attacker_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = 0,
        .sin_port = htons(ATTACKER_PORT)
    };
    inet_pton(AF_INET, ATTACKER_ADDRESS, &(attacker_addr.sin_addr));

    // 2. Attacker responds with experiment's tree (ascii byte in ["6", "7", "8", "9", "0", "1", "2"])
    char* msg = "start";
    char chosen_tree = '\0';
    while (chosen_tree == '\0') {
        int read_bytes = sendto(message_socket, msg, strlen(msg), 0, (struct sockaddr*) &attacker_addr, sizeof(attacker_addr));
        ESP_LOGI(TAG, "sent %s", msg);
        recv(message_socket, &chosen_tree, sizeof(chosen_tree), 0);
    }
    ESP_LOGI(TAG, "chosen_tree: %c", chosen_tree);

    // 3. Assign firewall function pointer to tree chosen by attacker
    firewall_statefull_fn = NULL;
    firewall_stateless_fn = NULL;
    is_firewall_stateless = true;
    switch (chosen_tree) {
        case '6':
            firewall_stateless_fn = decision_tree_depth_6;
            break;
        case '7':
            firewall_stateless_fn = decision_tree_depth_7;
            break;
        case '8':
            firewall_stateless_fn = decision_tree_depth_8;
            break;
        case '9':
            firewall_stateless_fn = decision_tree_depth_9;
            break;
        case '0':
            firewall_stateless_fn = decision_tree_depth_10;
            break;
        case '1':
            firewall_stateless_fn = decision_tree_depth_11;
            break;
        case '2':
            firewall_stateless_fn = decision_tree_depth_12;
            break;
        case 'r':
            firewall_statefull_fn = validate_packet;
            is_firewall_stateless = false;
            break;
        default:
            ESP_LOGE(TAG, "Invalid tree selected by attacker: %c", chosen_tree);
            return;
    }

    // 4. Signal that ESP32 assigned the tree previously sent and experiment is ready to begin
    msg = "assigned";
    ESP_LOGI(TAG, "%s", msg);
    int read_bytes = sendto(message_socket, msg, strlen(msg), 0, (struct sockaddr*) &attacker_addr, sizeof(attacker_addr));
    ESP_LOGI(TAG, "sent %s", msg);

    /*close(message_socket);*/
}

// This functions runs untils it receives the message b"D"
static void receive_experiment(const int sock, time_t experiment_duration)
{
    struct sockaddr_in listen_addr = { 0 };
    int recv_socket = iperf_run_tcp_server(&listen_addr); 
    ESP_LOGE(TAG, "recv_socket: %d", recv_socket);
    ESP_LOGE(TAG, "listen_addr: %s", inet_ntoa(listen_addr.sin_addr.s_addr));
    socklen_t socklen = sizeof(listen_addr);
    uint8_t *buffer = malloc(16 << 10);
    int want_recv = 16 << 10;
    
    is_finish = false;
    while (!is_finish) {
        int result = recvfrom(recv_socket, buffer, want_recv, 0, (struct sockaddr*)&listen_addr, &socklen);
        if (result < 0) {
            ESP_LOGE(TAG, "errno recv: %d", errno);
        } else {
            /* firewall_actual_len += result; */
        }
    }
    
    ESP_LOGW(TAG, "terminou iperf");

    int32_t len;
    char rx_buffer[3];
    do {
        len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0) {
            ESP_LOGE(TAG, "recv() error");
            perror(NULL);
        } else if (len == 0) {
            ESP_LOGE(TAG, "Connection close");
        } else {
            rx_buffer[len] = 0; // Null-terminate whatever is received and treat it like a string
            ESP_LOGI(TAG, "Received %d bytes: %s", len, rx_buffer);
        }
    } while (rx_buffer[0] != 'D');
}

static void udp_server_task(void *pvParameters)
{
    int message_sock = (int)pvParameters;
    /*ESP_LOGI(TAG, "NOSSA SOCKET UDP: %d", message_sock);*/
    // Wait for attacker to signalize experiment end
    receive_experiment(message_sock, 10);

    // Signal to attacker that esp will restart
    struct sockaddr_in attacker_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = 0,
        .sin_port = htons(ATTACKER_PORT)
    };
    inet_pton(AF_INET, ATTACKER_ADDRESS, &(attacker_addr.sin_addr));

    char* msg = "complete";
    int read_bytes = sendto(message_sock, msg, strlen(msg), 0, (struct sockaddr*) &attacker_addr, sizeof(attacker_addr));
    ESP_LOGI(TAG, "sent %s", msg);
    ESP_LOGI(TAG, "Experiment over, rebooting...");

    // Close all sockets and reboot
    shutdown(message_sock, SHUT_RD);
    close(message_sock);
    esp_restart();
}

void measurer_task(void *pvParameters) {
    int listen_sock = (int)(pvParameters);

    size_t stats_len = (uxTaskGetNumberOfTasks() * 50) + 100;
    char* runtime_stats = malloc(stats_len);
    if (runtime_stats == NULL) {
        ESP_LOGE(TAG, "malloc error sending_stats");
        return;
    }

    // Get stats from "wifi" task (which houses the lwip stack)
    TaskHandle_t wifi_task = xTaskGetHandle("wifi");
    if (!wifi_task) {
        ESP_LOGE(TAG, "wifi task not found");
        return;
    }

    // 6. Configure attacker UDP socket
    struct sockaddr_in attacker_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = 0,
        .sin_port = htons(ATTACKER_EXP_PORT)
    };
    inet_pton(AF_INET, ATTACKER_ADDRESS, &(attacker_addr.sin_addr));
    
    uint32_t cur = 0;
    uint32_t interval = 1;
    int experiment_duration = 10;
    while (cur < experiment_duration) {
        // Gather freertos tasks data
        ESP_LOGI(TAG, "Sending stats...");
        
        vTaskGetRunTimeStats(runtime_stats);

        int size_stats = strlen(runtime_stats);
        runtime_stats[size_stats] = '\0';

        // Generate and append Heap stats to collected data
        size_t heap_stats = heap_caps_get_total_size(MALLOC_CAP_8BIT | MALLOC_CAP_32BIT);
        sprintf(&runtime_stats[size_stats], "Heap\t%zu", heap_stats);

        size_stats = strlen(runtime_stats);
        runtime_stats[size_stats] = '\0';

        // Generate and append Stack stats to collected data
        UBaseType_t stack_stats = uxTaskGetStackHighWaterMark(wifi_task);
        sprintf(&runtime_stats[size_stats], "\r\nStack\t%u", stack_stats);

        // HEXDUMP for debug
        /*ESP_LOG_BUFFER_HEXDUMP(TAG, runtime_stats, stats_len, ESP_LOG_INFO);*/

        // Get network bandwidth stats
        size_stats = strlen(runtime_stats);
        runtime_stats[size_stats] = '\0';

        double actual_bandwidth = (firewall_actual_len / 1e6 * 8) / interval;
        sprintf(&runtime_stats[size_stats], "\r\nMbps\t%.2f", actual_bandwidth);
        printf("actual_bandwidth: %.2f", actual_bandwidth);
        cur += interval;
               
        // Reset network measuring after experiment.
        firewall_actual_len = 0;

        // Sending experiment data...
        int sent_bytes = sendto(listen_sock, runtime_stats, strlen(runtime_stats), 0, (struct sockaddr*) &attacker_addr, sizeof(attacker_addr));
        /*ESP_LOGI(TAG, "run_time_stats: %s", runtime_stats);*/
        ESP_LOGI(TAG, " len %d. Done.", sent_bytes);

        // Put the thread to sleep and do the next iteration after `sleep_duration`
        const TickType_t xDelay = 1000 / portTICK_PERIOD_MS;
        vTaskDelay(xDelay);

        // HEXDUMP das filas de pacote
        /*ESP_LOG_BUFFER_HEXDUMP(TAG, flow_queue.pq, TAM_FLOW*TAM*sizeof(struct pbuf), ESP_LOG_INFO);*/
    }
    is_finish = true;
}

// ESP32:    start
// Attacker: '6'
// ESP32:    assigned
// loop {
//  Esp32: collects then sends experiment data
//  sleep(1sec)
// }
// Attacker: 'D'
// ESP32: complete
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    int addr_family = (int)AF_INET;
    int ip_protocol = 0;
    struct sockaddr_storage dest_addr;

    // 1. Configuring our UDP socket
    if (addr_family == AF_INET) {
        struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&dest_addr;
        dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
        dest_addr_ip4->sin_family = AF_INET;
        dest_addr_ip4->sin_port = htons(PORT);
        ip_protocol = IPPROTO_IP;
    }

    // 2. Opening the UDP socket
    int message_sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (message_sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Socket created app_main");

    // 3. Binding our UDP socket so we can receive incoming packets
    int err = bind(message_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        ESP_LOGE(TAG, "IPPROTO: %d", addr_family);
    }
    ESP_LOGI(TAG, "Socket bound to port %d", PORT);

    init(message_sock);

#ifdef CONFIG_EXAMPLE_IPV4
    xTaskCreate(measurer_task, "measurer", 4096, (void *)message_sock, 4, NULL);
    xTaskCreate(udp_server_task, "udp_server", 4096, (void *)message_sock, 5, NULL);
#endif
}
