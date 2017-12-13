#include <iostream>
#include <pcap.h>
#include "interface.h"
#include "sniff.h"
#include <string>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;
int main(int argc, char **argv){
//	Interface iface;
	if(argc != 2){
		cout << "[*] Usage : ./pcap_test [interface name]" << endl;
		exit(0);
	}
	string iface(argv[1]);
//	Sniff sniff(iface.name);
	Sniff sniff(iface);
	sniff.start();
}	
