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

using namespace std;

Sniff::Sniff(string iface_name){

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
	uint32_t count = 0;
	uint32_t loop;
	cout << "[*] Start Packet Capture" << endl;
        while( 1) {
                const unsigned char *packet = NULL;
        	struct pcap_pkthdr *header;
                struct ether_header *eth;
                struct ip *iph;
                struct tcphdr *tcph;
                uint16_t ether_type;
		if(pcap_next_ex( this->handle, &header, &packet ) != 1)
			continue;
                eth = (struct ether_header *)packet;
                ether_type = htons(eth->ether_type);

		uint32_t ip_size;
		uint32_t tcp_size;
		uint32_t data_size;
                if (ether_type == ETHERTYPE_IP) { 	// IPv4 Packet 0x08 0x00
			count ++;
                        cout << endl << "["<< count << "] Caputrued! " << endl;
			print_mac( eth );
                        packet += sizeof(struct ether_header);
			iph = (struct ip *)packet;
			ip_size = iph->ip_hl *4;
			print_ip( iph );
			/*
			if(iph->ip_p == IPPROTO_TCP){	// TCP Packet 0x06
				print_ip( iph );
                        	packet += ip_size;
                        	tcph = (struct tcphdr *)packet;
				tcp_size = tcph->th_off *4;
                        	print_tcp(tcph);
				packet += tcp_size;
				data_size = (uint32_t)htons(iph->ip_len) - tcp_size;
				cout << "Data size : " << data_size << endl;	
			}
			*/
                }
        }
	cout << endl <<"[*] End Packet Capture" << endl;
}
