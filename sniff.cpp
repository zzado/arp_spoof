#include <iostream>
#include <pcap.h>
#include "interface.h"
#include "sniff.h"
#include <string>
#include <stdlib.h>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
using namespace std;

Sniff::Sniff(string iface_name, Node* sender, Node* target){
	this->sender = sender;
	this->target = target;
	this->iface_name = iface_name;
	this->handle = NULL;
}

void Sniff::print_mac(struct ether_header *eth){
        cout << "Src Mac : ";
	for (int i=0; i<6; i++)
		printf("%.2X ", eth->ether_shost[i]);        
	cout << " / Dest Mac :" ;                
	for (int i=0; i<6; i++)
		printf("%.2X ", eth->ether_dhost[i]);
	cout << endl;
}

void Sniff::print_ip(struct ip *iph){
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
	cout << "Src Ip : " << src_ip << " / ";
	cout << "Dest Ip : " << dst_ip << endl;
}

void Sniff::print_tcp(struct tcphdr *tcph){
        cout << "Src Port : " << htons(tcph->source) << " / ";
        cout << "Dest Port : " << htons(tcph->dest) << endl;
}

void Sniff::Pcap_open(){
	char *errbuf = NULL;
	this->handle = pcap_open_live(this->iface_name.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (this->handle == NULL){
                cout << errbuf << endl;
		exit(0);
	}
}

void Sniff::start(){
        Pcap_open();
        while( 1) {
                const unsigned char *packet = NULL;
        	struct pcap_pkthdr *header = NULL;
                struct ether_header *eth = NULL;
                struct ip *iph = NULL;
                uint16_t ether_type;
		if(pcap_next_ex( this->handle, &header, &packet ) != 1)
			continue;
                eth = (struct ether_header *)packet;
                ether_type = htons(eth->ether_type);
		uint32_t ip_size;
		uint32_t tcp_size;
		uint32_t data_size;

                if (ether_type == ETHERTYPE_IP ) { 	// IPv4 Packet 0x08 0x00
			if(!memcmp(eth->ether_shost, this->sender->mac_addr, 6) && !memcmp(eth->ether_dhost, this->sender->iface_mac_addr, 6)){				
                        //packet += sizeof(struct ether_header);
			//iph = (struct ip *)packet;
			//packet -= sizeof(struct ether_header);
			memcpy(eth->ether_shost, this->sender->iface_mac_addr, 6);
			memcpy(eth->ether_dhost, this->target->mac_addr, 6);
			pcap_sendpacket(this->handle, packet, header->len);
			}
			if(!memcmp(eth->ether_shost, this->target->mac_addr, 6) && !memcmp(eth->ether_dhost, this->sender->iface_mac_addr, 6)){
				packet += sizeof(struct ether_header);
                        	iph = (struct ip *)packet;
                        	packet -= sizeof(struct ether_header);
	//			if(!memcmp(ip_addr, this->sender->ip_addr, 4)){
					memcpy(eth->ether_shost, this->sender->iface_mac_addr, 6);
	                       		memcpy(eth->ether_dhost, this->sender->mac_addr, 6);
                		        pcap_sendpacket(this->handle, packet, header->len);
	//			}
		
			}
                
		}
        }
	cout << endl <<"[*] End Packet Capture" << endl;
}
