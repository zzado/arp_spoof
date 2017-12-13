#Makefile
CXXFLAGS="-std=c++11"

all: pcap_test

pcap_test: main.o sniff.o interface.o
	g++ -o pcap_test main.o interface.o sniff.o -lpcap

main.o: interface.h sniff.h main.cpp

interface.o: interface.h sniff.h interface.cpp

sniff.o: sniff.h interface.h sniff.cpp

clean:
	rm -f pcap_test
	rm -f *.o
