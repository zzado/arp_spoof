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
#include <cstring>

#include "spoof.h"
using namespace std;

Spoof::Spoof(string iface_name, Node* sender, Node* target){
	this->sender = sender;
	this->target = target;
	this->iface_name = iface_name;
	this->handle = NULL;
}

void Spoof::Pcap_open(){
	char *errbuf = NULL;
	this->handle = pcap_open_live(this->iface_name.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (this->handle == NULL){
                cout << errbuf << endl;
		exit(0);
	}
}

void Spoof::start(){
        Pcap_open();
        while( 1 ) {
                const unsigned char *packet = NULL;
        	struct pcap_pkthdr *header = NULL;
                struct ether_header *eth = NULL;
                struct ip *iph = NULL;
                uint16_t ether_type;
		if(pcap_next_ex( this->handle, &header, &packet ) != 1)
			continue;
                eth = (struct ether_header *)packet;
                ether_type = htons(eth->ether_type);

                if (ether_type == ETHERTYPE_IP ) {
			if(!memcmp(eth->ether_shost, this->sender->mac_addr, 6) && !memcmp(eth->ether_dhost, this->sender->iface_mac_addr, 6)){				
				memcpy(eth->ether_shost, this->sender->iface_mac_addr, 6);
				memcpy(eth->ether_dhost, this->target->mac_addr, 6);
				pcap_sendpacket(this->handle, packet, header->len);
			}
			if(!memcmp(eth->ether_shost, this->target->mac_addr, 6) && !memcmp(eth->ether_dhost, this->sender->iface_mac_addr, 6)){
                        	iph = (struct ip *)(packet + sizeof(struct ether_header));
				if(iph->ip_dst.s_addr == *(int *)this->sender->ip_addr){
					memcpy(eth->ether_shost, this->sender->iface_mac_addr, 6);
	                       		memcpy(eth->ether_dhost, this->sender->mac_addr, 6);
                		        pcap_sendpacket(this->handle, packet, header->len);
				}
		
			}
                
		}
        }
}
