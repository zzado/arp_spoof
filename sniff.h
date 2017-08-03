#include <string>
#include <netinet/if_ether.h>
#include <pcap.h>
class Sniff {
        public:
                void start();
                Sniff(std::string iface_name);
		
	private :
		void print_mac(struct ether_header *ep);
		void Pcap_open();
		void print_ip(struct ip *iph);
		void print_tcp(struct tcphdr *tcph);
 		pcap_t* handle;
                std::string iface_name;

};

