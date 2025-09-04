#include <stdio.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define MAX_MACS 50
static const char *TAG = "ESP_SNIFFER";

// Router BSSID to monitor - YOUR TARGET BSSID
// This is the MAC address of the Wi-Fi router.
uint8_t target_bssid[6] = {0xA4, 0x88, 0x73, 0x7C, 0x8A, 0x20};

typedef struct {
    uint8_t mac[6];
    int packet_count;
} mac_entry_t;

mac_entry_t mac_dict[MAX_MACS];
int dict_size = 0;

// Update MAC dictionary
void update_mac_dict(const uint8_t *mac) {
    for (int i = 0; i < dict_size; i++) {
        if (memcmp(mac_dict[i].mac, mac, 6) == 0) {
            mac_dict[i].packet_count++;
            return;
        }
    }
    if (dict_size < MAX_MACS) {
        memcpy(mac_dict[dict_size].mac, mac, 6);
        mac_dict[dict_size].packet_count = 1;
        dict_size++;
    }
}

// Promiscuous packet handler
static void sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = ppkt->payload;

    // --- Packet Filtering Logic ---
    const uint8_t *bssid = frame + 16;
    
    if (memcmp(bssid, target_bssid, 6) != 0) {
        return; 
    }

    const uint8_t *src_mac = frame + 10; 
    
    update_mac_dict(src_mac);

    // Extract other metadata
    int rssi = ppkt->rx_ctrl.rssi;
    int len = ppkt->rx_ctrl.sig_len;
    int channel = ppkt->rx_ctrl.channel;

    ESP_LOGI(TAG, "SRC: %02x:%02x:%02x:%02x:%02x:%02x | RSSI: %d | Len: %d | Ch: %d | Total MACs: %d",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
             rssi, len, channel, dict_size);
}

// Initialize Wi-Fi in promiscuous mode
void wifi_sniffer_init() {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Set the Wi-Fi channel to match your router's channel
    // We are now using your provided channel of '11'.
    ESP_ERROR_CHECK(esp_wifi_set_channel(11, WIFI_SECOND_CHAN_NONE));

    // Enable promiscuous mode and register the packet handler
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_handler);
}

// Main entry point
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_sniffer_init();
    ESP_LOGI(TAG, "ESP32 Sniffer Started...");
}
