#include <iostream>
#include <pcap.h>
#include "node.h"
#include <string>
#include <stdio.h>
#include "send_arp.h"
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <string.h>

using namespace std;
int main(int argc, char **argv){
//	Interface iface;
	if(argc != 4){
		cout << "[*] Usage : ./pcap_test [interface] [sender ip] [target ip]" <<endl;
		exit(0);
	}
	string iface(argv[1]);
	string _sender(argv[2]);
	string _target(argv[3]);
//	cout << iface << sender << target << endl;
	Node sender(iface, _sender);
	Node target(iface, _target);

	send_arp(&sender, &target, 100);
//	Sniff sniff(iface.name);
//	Sniff sniff(iface);
//	sniff.start();
}
