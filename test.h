#include <iostream>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>

struct ieee80211_radiotap_header {
	u_int8_t        it_version;     /* set to 0 */
	u_int8_t        it_pad;
	u_int16_t       it_len;         /* entire length */
} __attribute__((__packed__));

struct nextpresent{
	uint8_t flag;
	uint8_t datarate;
	uint16_t cf;
	uint16_t cflag;
	uint8_t pwr;
};

struct ieee80211_header {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t readdr1[6];
	uint8_t sourceaddr4[6];
	uint8_t bssid[6];
	uint16_t sequence_control;
};

struct beacon_frame_fixed {
	uint8_t timestamp[8];
	uint8_t beacon_interval[2]; 
	uint8_t capabilities_info[2];
};

struct info_element {
	uint8_t id;
	uint8_t length;
	uint8_t data[];
};

struct beacon_frame {
	struct ieee80211_header header;
	struct beacon_frame_fixed fixed;
	struct info_element ie[];
};

struct tag_rsn{
	uint8_t rsnid;
	uint8_t rsnlength;
	uint16_t version;
	uint32_t GroupCipherss;
	uint16_t pairwisesc;
};

struct csa{
	uint8_t tag_number = 0x25;
	uint8_t tag_len = 0x03;
	uint8_t channelswitch = 0x01;
	uint8_t new_channel = 0x13;
	uint8_t channel_switch_count = 0x03;
};
