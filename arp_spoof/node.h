#include <string>
#include <pcap.h>

using namespace std;

class Node{
	public:
		Node(string iface_name, string addr);
                string iface;
                string ip_addr_str;
		
		unsigned char mac_addr[6];
		unsigned char ip_addr[4];
                unsigned char iface_mac_addr[6];
		unsigned char iface_ip_addr[4];                
	private:
		void get_mac();
		void Pcap_open();
		pcap_t* handle;
};
