all: pcap-test

pcap-test: main.o homework.o
	g++ -o pcap-test main.o homework.o -lpcap

main.o: main.cpp homework.h
	g++ -c -o main.o main.cpp

homework.o: homework.cpp homework.h
	g++ -c -o homework.o homework.cpp

clean:
	rm -f *.o
	rm -f pcap-test
