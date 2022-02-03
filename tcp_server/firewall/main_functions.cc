#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/system_setup.h"
#include "tensorflow/lite/schema/schema_generated.h"

#include "include/model.h"
#include "include/stateless.h"

static const char *TAG = "LogisticRegression";

tflite::MicroErrorReporter micro_error_reporter;
tflite::ErrorReporter* error_reporter = &micro_error_reporter;

const tflite::Model* model = ::tflite::GetModel(g_model);

tflite::AllOpsResolver resolver;

const int tensor_arena_size = 2 * 44368;
uint8_t tensor_arena[tensor_arena_size];

tflite::MicroInterpreter interpreter(model, resolver, tensor_arena,
                                   tensor_arena_size, error_reporter);

TfLiteStatus allocate_status = interpreter.AllocateTensors();

err_t validate_packet(queue_t *q) {
    if (allocate_status != kTfLiteOk) {
        TF_LITE_REPORT_ERROR(error_reporter, "AllocateTensors() failed");
        return ERR_OK;
    }
    TfLiteTensor* input;
    /* ESP_LOGW(TAG, "DIM_SIZE: %d DIM_DATA: %d", input->dims->size, input->dims->data[0]); */
    for (int i = 0; i < MAX_QUARANTINE_SIZE; i++) {
        input = interpreter.input(i);
        ESP_LOGW(TAG, "DIM_SIZE: %d DIM_DATA: %d", input->dims->size, input->dims->data[0]);
        conn_headers_t *headers = &q->element[i].data.headers;
        struct ip_hdr *iphdr = headers->iphdr;
        struct tcp_hdr *tcphdr = headers->tcphdr;

        input->data.f[0]  = htons(IPH_ID(iphdr));
        input->data.f[1]  = (IPH_OFFSET(iphdr) & IP_DF);
        input->data.f[2]  = htons(IPH_LEN(iphdr));
        input->data.f[3]  = htons(IPH_TOS(iphdr)>>2);
        input->data.f[4]  = htons(tcphdr->seqno); 
        input->data.f[5]  = (htons(IPH_LEN(iphdr)) - htons(IPH_HL(iphdr))); //tcp_len
        input->data.f[6]  = TCPH_HDRLEN(tcphdr);
        input->data.f[7]  = (TCPH_FLAGS(tcphdr) & TCP_FIN);
        input->data.f[8]  = (TCPH_FLAGS(tcphdr) & TCP_SYN);
        input->data.f[9]  = (TCPH_FLAGS(tcphdr) & TCP_RST);
        input->data.f[10]  = (TCPH_FLAGS(tcphdr) & TCP_PSH);
        input->data.f[11] = (TCPH_FLAGS(tcphdr) & TCP_ACK);
        input->data.f[12] = (TCPH_FLAGS(tcphdr) & TCP_URG);
        input->data.f[13] = (TCPH_FLAGS(tcphdr) & TCP_CWR);
        input->data.f[14] = htons(tcphdr->wnd);
        input->data.f[15] = htons(tcphdr->urgp);
    }

    TfLiteStatus invoke_status = interpreter.Invoke();
    if (invoke_status != kTfLiteOk) {
        TF_LITE_REPORT_ERROR(error_reporter, "Invoke failed\n");
    }

    TfLiteTensor* output = interpreter.output(0);

  // Obtain the output value from the tensor
    float value = output->data.f[0];
    float value2 = output->data.f[1];

    return value < value2 ? ERR_ABRT : ERR_OK;
}

err_t mlp(struct ip_hdr *iphdr, struct tcp_hdr *tcphdr) {
  TfLiteTensor* input = interpreter.input(0);
  input->data.f[0]  = htons(IPH_ID(iphdr));
  input->data.f[1]  = (IPH_OFFSET(iphdr) & IP_DF);
  input->data.f[2]  = htons(IPH_LEN(iphdr));
  input->data.f[3]  = htons(IPH_TOS(iphdr)>>2);
  input->data.f[4]  = (htons(IPH_LEN(iphdr)) - htons(IPH_HL(iphdr)));
  input->data.f[5]  = TCPH_HDRLEN(tcphdr);
  input->data.f[6]  = (TCPH_FLAGS(tcphdr) & TCP_FIN);
  input->data.f[7]  = (TCPH_FLAGS(tcphdr) & TCP_SYN);
  input->data.f[8]  = (TCPH_FLAGS(tcphdr) & TCP_RST);
  input->data.f[9]  = (TCPH_FLAGS(tcphdr) & TCP_PSH);
  input->data.f[10] = (TCPH_FLAGS(tcphdr) & TCP_ACK);
  input->data.f[11] = (TCPH_FLAGS(tcphdr) & TCP_URG);
  input->data.f[12] = (TCPH_FLAGS(tcphdr) & TCP_CWR);
  input->data.f[13] = htons(tcphdr->wnd);
  input->data.f[14] = htons(tcphdr->urgp);

  TfLiteStatus invoke_status = interpreter.Invoke();
  if (invoke_status != kTfLiteOk) {
    TF_LITE_REPORT_ERROR(error_reporter, "Invoke failed\n");
  }

  TfLiteTensor* output = interpreter.output(0);

  // Obtain the output value from the tensor
  float value = output->data.f[0];
  float value2 = output->data.f[1];

  return value < value2 ? ERR_ABRT : ERR_OK;
}
