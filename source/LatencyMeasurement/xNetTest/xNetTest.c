#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

#define TCP_LAN_latency_TOPIC1            "device/TCP_LAN_latency"

// Logging macro
#define dbg_log1(fmt, ...)   fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

// Callback when a message arrives
void on_message(struct mosquitto *mosq, void *userdata,
                const struct mosquitto_message *msg)
{
    if (msg->payloadlen) {
        printf("Received on topic %s: %s\n", msg->topic, (char *)msg->payload);
        printf("✅ Success: Message received\n");
    } else {
        printf("Received empty message on topic %s\n", msg->topic);
    }
}

int main(void)
{
    struct mosquitto *mosq;
    int rc;

    mosquitto_lib_init();

    mosq = mosquitto_new("LatencySubscriber", true, NULL);
    if (!mosq) {
        dbg_log1("Failed to create Mosquitto client");
        mosquitto_lib_cleanup();
        return -1;
    }

    mosquitto_message_callback_set(mosq, on_message);

    rc = mosquitto_connect(mosq,
                           "192.168.245.254",
                           1883,
                           60);
    if (rc != MOSQ_ERR_SUCCESS) {
        dbg_log1("Failed to connect: %s", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return 1;
    }

    // Subscribe to the same topic publisher uses
    rc = mosquitto_subscribe(mosq, NULL, TCP_LAN_latency_TOPIC1, 1);
    if (rc != MOSQ_ERR_SUCCESS) {
        dbg_log1("Failed to subscribe: %s", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return 1;
    }

    dbg_log1("Subscribed to topic: %s", TCP_LAN_latency_TOPIC1);

    // Blocking loop to process messages
    mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}

