#Makefile
CXXFLAGS="-std=c++11"

all: send_arp

send_arp: node.o main.o interface.o send_arp.o sniff.o
	g++ -o send_arp node.o main.o interface.o send_arp.o sniff.o -lpcap -lpthread

main.o: interface.h node.h send_arp.h main.cpp

interface.o: interface.h interface.cpp

node.o: node.h node.cpp

sniff.o: sniff.cpp sniff.h

send_arp.o: send_arp.h node.h send_arp.cpp

clean:
	rm -f send_arp
	rm -f *.o
