#include <iostream>
#include <string>
#include <pcap.h>

using namespace std;

class Node{
	public:
		unsigned char mac_addr[6];
		string iface;
		string ip_addr_str;
		Node(string iface_name, string addr);
		unsigned char ip_addr[4];
                unsigned char iface_mac_addr[6];
		unsigned char iface_ip_addr[4];                
	private:
		void get_mac();
		void Pcap_open();
		pcap_t* handle;
};
