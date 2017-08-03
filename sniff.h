#include <string>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "node.h"
using namespace std;
class Sniff {
        public:
                void start();
		Sniff(string iface_name, Node* sender, Node* target);
		Node *target;
		Node *sender;
	private :
		void print_mac(struct ether_header *ep);
		void Pcap_open();
		void print_ip(struct ip *iph);
		void print_tcp(struct tcphdr *tcph);
 		pcap_t* handle;
                std::string iface_name;

};

