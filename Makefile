#Makefile
CXXFLAGS="-std=c++11"

all: arp_spoof

arp_spoof: node.o main.o send_arp.o spoof.o
	g++ -o arp_spoof node.o main.o send_arp.o spoof.o -lpcap -lpthread

main.o: node.h send_arp.h main.cpp

node.o: node.h node.cpp

spoof.o: spoof.cpp spoof.h

send_arp.o: send_arp.h node.h send_arp.cpp

clean:
	rm -f send_arp
	rm -f *.o
