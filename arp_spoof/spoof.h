#include <string>
#include <pcap.h>
#include "node.h"
using namespace std;
class Spoof {
        public:
                void start();
		Spoof(string iface_name, Node* sender, Node* target);
		Node *target;
		Node *sender;
	private :
		void Pcap_open();
 		pcap_t* handle;
                std::string iface_name;

};

