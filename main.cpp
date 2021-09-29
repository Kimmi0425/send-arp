#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

char myip[16];
unsigned char mymac[32];

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


int ip_my(char* dev, char* myip){
	u_int32_t i;
	struct ifreq ifr;
	char ipstr[20];
	u_int32_t s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	ioctl(s, SIOCGIFADDR, &ifr);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
	printf("my IP address is %s\n", ipstr);
	memcpy(myip, ipstr, strlen(ipstr));


	return 0;
}

int mac_my(char *dev, unsigned char* mymac){
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);

	memcpy(mymac, ifr.ifr_hwaddr.sa_data, 6);
	printf("my MAC address is %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0], mymac[1], mymac[2], mymac[3], mymac[4], mymac[5]);
	return 0;

}

int send_arp(pcap_t* handle, char* sender_ip, char* target_ip, unsigned char* mymac, unsigned char* yourmac, uint16_t op) {

	EthArpPacket packet;
	
	if (op == 1) {
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.op_ = htons(ArpHdr::Request);
	} 
	else if (op == 2) {
		packet.eth_.dmac_ = Mac(yourmac);
		packet.arp_.tmac_ = Mac(yourmac);
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tip_ = htonl(Ip(target_ip));

	if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
		fprintf(stderr, "couldn't send packet : %s\n", pcap_geterr(handle));
		return -1;
	}

	printf("send arp from '%s' to '%s'\n",sender_ip,target_ip);
	printf("my mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);
	printf("your mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", yourmac[0],yourmac[1],yourmac[2],yourmac[3],yourmac[4],yourmac[5]);

	printf("sendarp end\n");
	return 0;
}

int getyourmac(pcap_t* handle, char* myip, char* yourip, unsigned char* mymac,unsigned char* yourmac){
	printf("getyourmac start\n");
    while(true){
        send_arp(handle, myip, yourip, mymac, yourmac, 1);
		struct pcap_pkthdr* header;
		const u_char* _packet;
		
		int res = pcap_next_ex(handle, &header, &_packet);

		EthHdr* eth_ = (EthHdr*) _packet;
	
		ArpHdr* arp_ = (ArpHdr*) ((uint8_t*)(_packet) + 14);
		
		memcpy(yourmac,(u_char*)arp_->smac_, 6);
		printf("your mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", yourmac[0],yourmac[1],yourmac[2],yourmac[3],yourmac[4],yourmac[5]);
		break;
    }
	printf("getyourmac end\n");
	return 0;
}   



int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	Ip sip = Ip(argv[2]);
	Ip tip = Ip(argv[3]);
	
	Mac smac;
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	ip_my(dev,myip);
	mac_my(dev,mymac);
	
	EthArpPacket *etharp;
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		if (packet == NULL) continue;
        
		etharp = (EthArpPacket *) packet;
		
		if(etharp->eth_.type() != EthHdr::Arp) 
			continue;
		if(etharp->arp_.hrd() != ArpHdr::ETHER || etharp->arp_.pro() != EthHdr::Ip4 || etharp->arp_.op() != ArpHdr::Reply)
			continue;

		if(Mac(mymac) == etharp->arp_.tmac() && Ip(myip) == etharp->arp_.tip() && Ip(sip) == etharp->arp_.sip()) {

			printf("my mac: %s\n", mymac);
			break;
		}
	}

	smac = etharp->arp_.smac();
	printf("caught sender's mac address\n");
	

	pcap_close(handle);

}
