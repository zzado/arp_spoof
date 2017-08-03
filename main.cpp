#include <iostream>
#include <pcap.h>
#include "interface.h"
#include "sniff.h"
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
#include <netinet/in.h>
#include <string.h>

#include <thread>

using namespace std;

int status = 0;
int main(int argc, char **argv){
//	Interface iface;
/*
	if(argc != 4){
		cout << "[*] Usage : ./pcap_test [interface] [sender ip] [target ip]" <<endl;
		exit(0);
	}
*/
	string iface("ens33");
	string _sender("192.168.86.133");
	string _target("192.168.86.2");
	Node sender(iface, _sender);
	Node target(iface, _target);

	thread infect(send_arp, &sender, &target);
	thread infect2(send_arp, &target, &sender);
//	sleep(3);
//	ift.send_arp(&sender, &target, 100);
	//sleep(1000);
	//status = 1;
	unsigned char my_ip[4] = {192, 168, 86, 131};
	Sniff sniff(iface, &sender, &target);
	sniff.start();
	infect.join();
        infect2.join();

}
