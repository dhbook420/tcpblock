#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "mac.h"

#include <iostream>
#include <thread>
#include <cstring>
#include <algorithm>
#include <pcap.h>

using namespace std;

void usage() {
    cout << "\nsyntax : tcp-block <interface> <pattern>\nsample : tcp-block wlan0 \"Host: test.gilgil.net\"\n";
}

struct Packet{
    EthHdr eth;
    IpHdr ip;
    TcpHdr tcp;
};

bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr);
bool tcp_block(const uint8_t* pkt, string &host, pcap_t* pcap, string iface);
void send_packet(const string& iface,
                 pcap_t*     handle,
                 const EthHdr* eth,
                 const IpHdr*  ip,
                 const TcpHdr* tcp,
                 const char*   payload,
                 int           recv_len,
                 bool          is_forward);
int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }

    string iface(argv[1]);
    string host(argv[2]);
    Mac mac;
    Ip ip;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (!getMacIpAddr(iface, mac, ip))
        return EXIT_FAILURE;


    pcap_t* pcap = pcap_open_live(iface.c_str(), 65536, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", iface.c_str(), errbuf);
        return EXIT_FAILURE;
    }


    size_t pos = host.find(":");
    if (pos == string::npos) {
        return 1;
    }

    host = host.substr(pos+2);
    if (!host.empty() && host.back() == '\n') {
        host.pop_back();
    }
    if (!host.empty() && host.back() == '\r') {
        host.pop_back();
    }

    cout << host << endl;

    while (true){
        struct pcap_pkthdr *header;
        const uint8_t* pkt;
        int res = pcap_next_ex(pcap, &header, &pkt);
        if (res == 0){
            continue;
        }
        if (res==PCAP_ERROR||res==PCAP_ERROR_BREAK){
            break;
        }

        tcp_block(pkt, host, pcap, iface);
            
    }
    pcap_close(pcap);
    return 0;

}

bool tcp_block(const uint8_t* pktbuf, string &host, pcap_t* pcap, string iface)
{
    char tcp_data[63] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";

    //Ip4
    const EthHdr* eth = reinterpret_cast<const EthHdr*>(pktbuf);
    uint16_t eth_type = eth->type();

    if (eth_type != EthHdr::Ip4) {
        return false;
    }

    //tcp
    const uint8_t* ip_start = pktbuf + sizeof(EthHdr);
    const IpHdr* ip = reinterpret_cast<const IpHdr*>(ip_start);
    uint8_t ihl = (ip->version_and_ihl & 0x0F);
    size_t ip_header_len = static_cast<size_t>(ihl) * 4;

    if ((ip_header_len < 20) || (ip->protocol != IpHdr::TCP) ) {
        return false;
    }

    const uint8_t* tcp_start = ip_start + ip_header_len;
    const TcpHdr* tcp = reinterpret_cast<const TcpHdr*>(tcp_start);

    uint8_t data_offset = (tcp->th_off) & 0x0F;
    size_t tcp_header_len = static_cast<size_t>(data_offset) * 4;

    if (tcp_header_len < 20) {
        return false;
    }

    const uint8_t* payload = tcp_start + tcp_header_len;
    uint16_t ip_total_len = ntohs(ip->total_length);
    size_t payload_len = 0;

    if (ip_total_len > ip_header_len + tcp_header_len) {
        payload_len = static_cast<size_t>(ip_total_len) - ip_header_len - tcp_header_len;
    } else {
        payload_len = 0;
    }

    if (payload_len == 0) {
        return false;
    }

    const uint8_t* begin = payload;
    const uint8_t* end   = payload + payload_len;
    const uint8_t* pat_b = reinterpret_cast<const uint8_t*>(host.data());
    const uint8_t* pat_e = pat_b + host.size();

    auto it = search(begin, end, pat_b, pat_e);
    if (it != end) {
        
        send_packet(iface, pcap, eth, ip, tcp, tcp_data, static_cast<int>(payload_len) , false);
        send_packet(iface, pcap, eth, ip, tcp, nullptr, static_cast<int>(payload_len) , true);
        return true;
    }

    return false;
}

bool getMacIpAddr(string &iface_name, Mac& mac_addr, Ip& ip_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return false;
    }
    struct ifreq ifr {};
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(failed to get mac addr)");
        close(fd);
        return false;
    }
    Mac mac(reinterpret_cast< uint8_t*>(ifr.ifr_hwaddr.sa_data));
    mac_addr = mac;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl(failed to get ip addr)");
        close(fd);
        return false;
    }
    Ip ip_tmp(ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr));
    ip_addr = ip_tmp;

    close(fd);
    return true;
}

void send_packet(const string& iface,
                 pcap_t*     handle,
                 const EthHdr* eth,
                 const IpHdr*  ip,
                 const TcpHdr* tcp,
                 const char*   payload,
                 int           recv_len,
                 bool          is_forward)
{
    int eth_len = sizeof(EthHdr);
    int ip_len  = sizeof(IpHdr);
    int tcp_len = sizeof(TcpHdr);
    int payload_len = payload ? static_cast<int>(strlen(payload)) : 0;
    int packet_len = eth_len + ip_len + tcp_len + payload_len;

    // (1) 헤더 복사본 생성
    EthHdr new_eth;
    IpHdr  new_ip;
    TcpHdr new_tcp;

    // ── 이더넷 헤더 복사 및 수정 ──
    memcpy(&new_eth, eth, eth_len);
    if (!is_forward) {
        // 역방향(서버→클라이언트)이면 목적지 MAC을 원래 출발지 MAC으로 바꿈
        new_eth.dmac_ = eth->smac_;
    }
    // 인터페이스의 MAC 주소를 직접 가져와서 source MAC으로 설정
    Mac our_mac;
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct ifreq ifr {};
            ifr.ifr_addr.sa_family = AF_INET;
            strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) != -1) {
                our_mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
            }
            close(fd);
        }
    }
    new_eth.smac_ = our_mac;


    // ── IP 헤더 복사 및 수정 ──
    memcpy(&new_ip, ip, ip_len);
    if (!is_forward) {
        // 서버→클라이언트 방향일 때: 출발지/목적지 IP 뒤바꾸고 TTL 초기화
        new_ip.sip_ = ip->dip_;
        new_ip.dip_ = ip->sip_;
        new_ip.ttl  = 128;
    }
    // 총길이 필드 재설정 (IP 헤더 + TCP 헤더 + payload)
    new_ip.total_length = htons(static_cast<uint16_t>(ip_len + tcp_len + payload_len));
    new_ip.checksum = 0;
    // IP 체크섬 재계산 (간단한 방식)
    auto ip_checksum = [](const IpHdr* iph)->uint16_t {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(iph);
        int sum = 0;
        for (int i = 0; i < (sizeof(IpHdr) / 2); i++) {
            sum += ntohs(ptr[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        return htons(static_cast<uint16_t>(~sum & 0xFFFF));
    };
    new_ip.checksum = ip_checksum(&new_ip);


    // ── TCP 헤더 복사 및 수정 ──
    memcpy(&new_tcp, tcp, tcp_len);
    if (is_forward) {
        // 클라이언트→서버 방향: RST+ACK, seq += recv_len
        new_tcp.th_flags = static_cast<uint8_t>(TcpHdr::RST) 
                         | static_cast<uint8_t>(TcpHdr::ACK);
        new_tcp.th_seq   = htonl(ntohl(tcp->th_seq) + recv_len);
        new_tcp.th_ack   = tcp->th_ack;
    }
    else {
        // 서버→클라이언트 방향: 출발지/목적지 포트 뒤바꾸기 + FIN+ACK
        new_tcp.th_sport = tcp->th_dport;
        new_tcp.th_dport = tcp->th_sport;
        new_tcp.th_flags = static_cast<uint8_t>(TcpHdr::FIN) 
                         | static_cast<uint8_t>(TcpHdr::ACK);
        new_tcp.th_seq   = tcp->th_ack;
        new_tcp.th_ack   = htonl(ntohl(tcp->th_seq) + recv_len);
    }
    // 데이터 오프셋 설정 (20바이트 = 5 * 4)
    new_tcp.th_off = static_cast<uint8_t>(tcp_len / 4);
    new_tcp.th_x2  = 0;   // 예약 비트 4비트
    
    new_tcp.th_win   = 0;
    new_tcp.th_urp   = 0;
    new_tcp.th_sum   = 0; // 이후에 체크섬을 계산할 예정

    // ── TCP 체크섬 계산을 위한 Pseudo Header 구성 ──
    struct PseudoHdr {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    } psh;

    psh.src_addr = new_ip.sip_;
    psh.dst_addr = new_ip.dip_;
    psh.zero     = 0;
    psh.protocol = IpHdr::TCP;
    psh.tcp_len  = htons(static_cast<uint16_t>(tcp_len + payload_len));

    int cksum_buf_len = sizeof(PseudoHdr) + tcp_len + payload_len;
    uint8_t* cksum_buf = static_cast<uint8_t*>(malloc(cksum_buf_len));
    memcpy(cksum_buf, &psh, sizeof(PseudoHdr));
    memcpy(cksum_buf + sizeof(PseudoHdr), &new_tcp, tcp_len);
    if (payload_len > 0) {
        memcpy(cksum_buf + sizeof(PseudoHdr) + tcp_len, payload, payload_len);
    }
    // TCP 체크섬 계산 함수
    auto tcp_checksum = [](const uint8_t* buf, int len)->uint16_t {
        int sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buf);
        for (int i = 0; i < (len / 2); i++) {
            sum += ntohs(ptr[i]);
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        if (len & 1) {
            // 남은 1바이트 처리
            sum += (buf[len - 1] << 8) & 0xFF00;
            if (sum > 0xFFFF) sum = (sum & 0xFFFF) + 1;
        }
        return htons(static_cast<uint16_t>(~sum & 0xFFFF));
    };
    new_tcp.th_sum = tcp_checksum(cksum_buf, cksum_buf_len);
    free(cksum_buf);


    // ── 최종 패킷 버퍼 조립 ──
    uint8_t* packet = static_cast<uint8_t*>(malloc(packet_len));
    memcpy(packet, &new_eth, eth_len);
    memcpy(packet + eth_len, &new_ip, ip_len);
    memcpy(packet + eth_len + ip_len, &new_tcp, tcp_len);
    if (payload_len > 0) {
        memcpy(packet + eth_len + ip_len + tcp_len, payload, payload_len);
    }


    // ── 전송 ──
    if (is_forward) {
        // pcap을 사용하여 Ethernet 헤더 포함 전체 패킷 송출
        if (pcap_sendpacket(handle,
                            reinterpret_cast<const u_char*>(packet),
                            packet_len) != 0)
        {
            fprintf(stderr, "pcap_sendpacket 실패: %s\n", pcap_geterr(handle));
        }
    }
    else {
        // RAW 소켓을 열어 IP 헤더부터 보내기 (Ethernet 헤더는 제외)
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            fprintf(stderr, "RAW socket 생성 실패: %s\n", strerror(errno));
            free(packet);
            return;
        }
        int one = 1;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        struct sockaddr_in dst{};
        dst.sin_family      = AF_INET;
        dst.sin_port        = new_tcp.th_sport;    // RAW에서는 큰 의미 없음
        dst.sin_addr.s_addr = new_ip.dip_;

        if (sendto(sockfd,
                   packet + eth_len,
                   packet_len - eth_len,
                   0,
                   reinterpret_cast<struct sockaddr*>(&dst),
                   sizeof(dst)) < 0)
        {
            perror("sendto 실패");
        }
        close(sockfd);
    }

    free(packet);
}