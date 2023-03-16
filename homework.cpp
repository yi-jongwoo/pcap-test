#include "homework.h"
#include <stdio.h>
#include <netinet/in.h>

#define TOKEN_PASTE(x, y) x##y
#define CAT(x,y) TOKEN_PASTE(x,y)
#define ignore_bytes(n) uint8_t CAT(nevermind,__LINE__)[n];

constexpr int is_little_endian(){
	uint16_t x=1;
	return *(uint8_t*)&x;
}

void print_byte(uint8_t x){
	printf("%x%x",x/16,x%16);
}

void print_hex(const uint8_t* payload,int len){
	printf("payload(%d bytes) : ",len);
	if(len>10)len=10;
	for(int i=0;i<len;i++)
		print_byte(payload[i]);
	printf("\n");
}

struct tcp_header{
	uint16_t src;
	uint16_t dst;
	ignore_bytes(8)
	uint8_t header_size_big : 4;
	uint8_t header_size_little : 4;
	ignore_bytes(7)
	uint32_t upper_layer[1];
	void prn(int len){
		int header_size=is_little_endian()?header_size_little:header_size_big;
		printf("TCP port src: %hu dst: %hu\n",ntohs(src),ntohs(dst));
		print_hex((uint8_t*)(upper_layer+header_size-5),len-header_size*4);
	}
}__attribute__((packed));

struct ipv4_addr{
	uint8_t addr[4];
	void prn(){
		printf("%hhu",addr[0]);
		for(int i=1;i<4;i++)
			printf(".%hhu",addr[i]);
	}
}__attribute__((packed));

struct ipv4_header{
	uint8_t header_size_little : 4;
	uint8_t header_size_big : 4;
	
	ignore_bytes(1)
	uint16_t ip_size;
	ignore_bytes(5)
	uint8_t protocall;
	ignore_bytes(2)
	ipv4_addr src;
	ipv4_addr dst;
	uint32_t upper_layer[1];
	int is_tcp(){
		return protocall==0x06;
	}
	void prn(){
		int header_size=is_little_endian()?header_size_little:header_size_big;
		printf("IPv4 src: ");
		src.prn();
		printf(" dst: ");
		dst.prn();
		printf("\n");
		((tcp_header*)(upper_layer+header_size-5))->prn(ntohs(ip_size));
	}
}__attribute__((packed));

struct ipv6_addr{
	uint8_t addr[16];
	void prn(){
		for(int i=0;i<8;i++){
			if(i)printf("::");
			print_byte(addr[i<<1]);
			print_byte(addr[i<<1|1]);
		}
	}
}__attribute__((packed));

struct ipv6_header{
	ignore_bytes(4)
	uint16_t ip_size;
	uint8_t protocall;
	ignore_bytes(1);
	ipv6_addr src;
	ipv6_addr dst;
	uint32_t upper_layer[1];
	int is_tcp(){
		return protocall==0x06;
	}
	void prn(){
		printf("IPv6 src: ");
		src.prn();
		printf(" dst: ");
		dst.prn();
		printf("\n");
		((tcp_header*)upper_layer)->prn(ntohs(ip_size));
	}
}__attribute__((packed));

struct mac_addr{
	uint8_t addr[6];
	void prn(){
		for(int i=0;i<6;i++){
			if(i)printf("-");
			print_byte(addr[i]);
		}
	}
}__attribute__((packed));

struct eth_header{
	mac_addr dst;
	mac_addr src;
	uint16_t typ;
	uint8_t upper_layer[1];
	void prn(){
		if(ntohs(typ)==0x0800 && ((ipv4_header*)upper_layer)->is_tcp()){
			printf("MAC src: ");
			src.prn();
			printf(" dst: ");
			dst.prn();
			printf("\n");
			((ipv4_header*)upper_layer)->prn();
		}
		else if(ntohs(typ)==0x86DD && ((ipv6_header*)upper_layer)->is_tcp()){
			printf("MAC src: ");
			src.prn();
			printf(" dst: ");
			dst.prn();
			printf("\n");
			((ipv6_header*)upper_layer)->prn();
		}
		else
			printf("[-] not TCP/IP packet\n");
		
	}
}__attribute__((packed));

void print_tcp_packet(const uint8_t* packet){
	((eth_header*)packet)->prn();
	printf("\n");
}
