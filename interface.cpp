#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include "interface.h"
using namespace std;

Interface::Interface(){
	this->find_interface();
}

void Interface::find_interface(){
        char* errbuf = NULL;
        pcap_if_t *alldevs;
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
                cout << errbuf << endl;
                return ;
        }
        int i=0;
        vector<string> v;
        cout << "[*] Select network interface"<< endl << endl;

        while( alldevs->next != NULL){
                if(alldevs -> flags ==0){
                        alldevs = alldevs->next;
                        continue;
                }
                if(alldevs->name !=NULL) cout<< i << ". "<< alldevs->name << endl;
                v.push_back(string(alldevs->name));
                alldevs = alldevs->next;
                i++;
        }

	cout << endl <<"[*] Select Device : ";
        int select_device;
        cin >> select_device;
	this->name = v[select_device];
}
