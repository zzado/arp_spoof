#Makefile
CXXFLAGS="-std=c++11"

all: send_arp

send_arp: node.o main.o send_arp.o
	g++ -o send_arp node.o main.o send_arp.o -lpcap

main.o: node.h send_arp.h main.cpp

node.o: node.h node.cpp

send_arp.o: send_arp.h node.h send_arp.cpp

clean:
	rm -f send_arp
	rm -f *.o
