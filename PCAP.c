#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>              // 패킷 캡처용 libpcap 헤더
#include <arpa/inet.h>         // IP 주소 변환 함수용 헤더
#include <netinet/ether.h>     // MAC 주소 문자열 변환 함수 포함
#include <string.h>            // 문자열 처리용

// 1. 이더넷 헤더 구조체
struct ethheader {
    u_char ether_dhost[6];    // 목적지 MAC 주소 (6바이트)
    u_char ether_shost[6];    // 출발지 MAC 주소 (6바이트)
    u_short ether_type;       // 상위 프로토콜 타입 (IP = 0x0800)
};

// 2. IP 헤더 구조체
struct ipheader {
    u_char iph_ihl:4, iph_ver:4;     // IP 헤더 길이&IP 버전
    u_char iph_tos;                
    u_short iph_len;                // 전체 IP 패킷 길이 
    u_short iph_ident;              // 식별자
    u_short iph_flag:3, iph_offset:13; // 플래그 + 오프셋
    u_char iph_ttl;                 // TTL (Time to Live)
    u_char iph_protocol;            // 상위 프로토콜
    u_short iph_chksum;             // 헤더 체크섬
    struct in_addr iph_sourceip;    // 출발 IP 주소
    struct in_addr iph_destip;      // 목적 IP 주소
};

// 3. TCP 헤더 구조체
struct tcpheader {
    u_short tcp_sport;        // 출발 포트 번호
    u_short tcp_dport;        // 목적 포트 번호
    u_int tcp_seq;            // 시퀀스 번호
    u_int tcp_ack;            // ACK 번호
    u_char tcp_offx2;         // 데이터 오프셋 예약 필드
    u_char tcp_flags;         // 플래그 필드
    u_short tcp_win;          // 윈도우 크기
    u_short tcp_sum;          // 체크섬
    u_short tcp_urp;          // 긴급 포인터
};

// 4. 캡처된 패킷 콜백 함수
void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Ethernet 헤더 파싱
    struct ethheader *eth = (struct ethheader *)packet;

    // Ethernet 타입이 IP가 아닐 시, 무시
    if (ntohs(eth->ether_type) != 0x0800)
        return;

    // IP 헤더 파싱
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    // 상위 프로토콜이 TCP가 아닐 시, 무시
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    // IP 헤더 길이 계산 
    int ip_header_len = ip->iph_ihl * 4;

    // TCP 헤더 파싱 
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // TCP 헤더 길이 계산
    int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;

    // Payload 시작 위치 계산
    const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;

    // Payload 길이 계산
    int payload_len = header->caplen - (payload - packet);

   
    // Ethernet 정보 출력
    printf("[Ethernet] Src MAC: %s | Dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost), ether_ntoa((struct ether_addr *)eth->ether_dhost));

    // IP 정보 출력
    printf("[IP] Src IP: %s | Dst IP: %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));    

    // TCP 포트 정보 출력
    printf("[TCP] Src Port: %d | Dst Port: %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));      

    // Payload 일부 출력 (최대 16바이트)
    printf("[Payload] ");
    int len = payload_len > 16 ? 16 : payload_len;
    for (int i = 0; i < len; i++) {
        // ASCII 출력 가능한 문자만 출력, 아니면 .으로 대체
        if (isprint(payload[i]))
            printf("%c", payload[i]);
        else
            printf(".");
    }
    printf("\n\n");
}

// 5. 메인
int main() {
    pcap_t *handle;                          // 패킷 캡처 핸들
    char errbuf[PCAP_ERRBUF_SIZE];          // 에러 메시지 버퍼
    struct bpf_program fp;                  // 필터 구조체
    char filter_exp[] = "tcp";              // 캡처 필터 (TCP만 캡처)
    bpf_u_int32 net = 0;                    // 네트워크 번호 (기본값 사용)

    // Step 1: Open session
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}