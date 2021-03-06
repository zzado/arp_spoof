#include <iostream>
#include <pcap.h>
#include <string>
#include <stdlib.h>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "node.h"
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

using namespace std;

Node::Node(string iface_name, string addr){
	cout << "[*] Send ARP request message to " << addr << endl;
	this->iface = iface_name;
	this->ip_addr_str = addr;
	inet_pton(AF_INET, addr.c_str() ,this->ip_addr);
///
	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        strcpy(ifr.ifr_name, this->iface.c_str());
        ioctl(s, SIOCGIFHWADDR, &ifr);
	memcpy(this->iface_mac_addr, ifr.ifr_hwaddr.sa_data, 6);        	
/*
	for(int i=0; i<6; i++)
		printf("%.2X ", this->iface_mac_addr[i]);
*/
	close(s);
////	
	
	get_mac();	
}
void Node::Pcap_open(){
        char *errbuf = NULL;
        this->handle = pcap_open_live(this->iface.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (this->handle == NULL){
                cout << errbuf << endl;
                exit(0);
        }
}


void Node::get_mac(){
        Pcap_open();
	u_char packet[100];
	int i=0;
	int packet_length = 0;
        u_char dest_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };	// Broad cast
        u_char sender_ip[] = { 0xc0, 0xa8, 0x56, 0x83 };		// Myip
        u_char target_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        u_char ether_type[] = { 0x08, 0x06 };           //ARP
        u_char Hardware_Type[] = { 0x00,0x01 };         //ETHERNET
        u_char Protocol_Type[] = { 0x08,0x00 };         //IP
        u_char Hardware_Size[] = { 0x06 };
        u_char Protocol_Size[] = { 0x04 };		
        u_char Opcode[] = { 0x00, 0x01 };                       //Request
	
	memcpy(packet + i, dest_mac, sizeof(dest_mac));
	i += sizeof(dest_mac);
	memcpy(packet + i, this->mac_addr, sizeof(this->mac_addr));	// src mac
        i += sizeof(this->mac_addr);
	memcpy(packet + i, ether_type, sizeof(ether_type));
        i += sizeof(ether_type);
	memcpy(packet + i, Hardware_Type, sizeof(Hardware_Type));
        i += sizeof(Hardware_Type);
	memcpy(packet + i, Protocol_Type, sizeof(Protocol_Type));
        i += sizeof(Protocol_Type);
	memcpy(packet + i, Hardware_Size, sizeof(Hardware_Size));
        i += sizeof(Hardware_Size);
	memcpy(packet + i, Protocol_Size, sizeof(Protocol_Size));
        i += sizeof(Protocol_Size);
	memcpy(packet + i, Opcode, sizeof(Opcode));
        i += sizeof(Opcode);
	memcpy(packet + i, this->mac_addr, sizeof(this->mac_addr));	// sender_mac
        i += sizeof(this->mac_addr);
	memcpy(packet + i, sender_ip, sizeof(sender_ip));
        i += sizeof(sender_ip);
	memcpy(packet + i, target_mac, sizeof(target_mac));		//traget mac
        i += sizeof(target_mac);
	memcpy(packet + i, this->ip_addr, sizeof(this->ip_addr));	//target ip
        i += sizeof(this->ip_addr);

//        for(int i=0; i<100; i++)
	//	pcap_sendpacket(this->handle, packet, 100);
	int count = 0;
	while( 1 ) {
		if(count > 10){
			cout << "[*] " << ip_addr_str << " doesn't response ARP"<< endl;
			exit(0);
		}
		pcap_sendpacket(this->handle, packet, 100);
                count++;
		const unsigned char *recv_packet = NULL;
                struct pcap_pkthdr *header;
                struct ether_header *eth;
                uint16_t ether_type;
		struct ether_arp *arp;
		char buf[30];
		char buf2[30];
                if(pcap_next_ex( this->handle, &header, &recv_packet ) != 1)
                        continue;
                eth = (struct ether_header *)recv_packet;
                ether_type = htons(eth->ether_type);
		if (ether_type == ETHERTYPE_ARP){
			recv_packet += sizeof(struct ether_header);
			arp = (struct ether_arp *)recv_packet;
			if( ntohs(arp->ea_hdr.ar_op) == 2){ 		// is reply?
				if( !memcmp(this->ip_addr, arp->arp_spa, 4) ){
					memcpy(this->mac_addr, arp->arp_sha, 6);
					cout << "[*] " << ip_addr_str << "'s Mac address is ";
					for(int i=0; i<6; i++)
						printf("%.2X ", this->mac_addr[i]);
					cout << endl;
					pcap_close(this->handle);
					break;
				}
			}
		}		
	}
}

