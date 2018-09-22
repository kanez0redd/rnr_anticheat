/* This code will query a ntp server for the local time and display

* it.  it is intended to show how to use a NTP server as a time
* source for a simple network connected device.
* This is the C version.  The orignal was in Perl
*
* For better clock management see the offical NTP info at:
* http://www.eecis.udel.edu/~ntp/
*
* written by Tim Hogard (thogard@abnormal.com)
* Thu Sep 26 13:35:41 EAST 2002
* Converted to C Fri Feb 21 21:42:49 EAST 2003
* this code is in the public domain.
* it can be found here http://www.abnormal.com/~thogard/ntp/
*
*/

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include "main.h"
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
#include "NtpClient.h"




#define debug 1
#define TIMEOUT 2
#define JAN_1970 0x83AA7E80
#define NTP_SERVER_1 "200.20.186.76" 


void construct_ntp_packet(char content[])
{
	long           timer;

	memset(content, 0, 48);
	content[0] = 0x1b; 			// LI = 0 ; VN = 3 ; Mode = 3 (client);

	time((time_t *)&timer);
	timer = htonl(timer + JAN_1970);

	//	printf("construct_ntp_packet memcpy\n");
	memcpy(content + 40, &timer, sizeof(timer));  //trans_timastamp

												  //	printf("construct_ntp_packet memcpy end\n");
}

int get_ntp_time(int sockfd, struct sockaddr_in *server_addr)
{
	long temp;
	time_t timet;
	int            addr_len = 16;
	struct timeval block_time;
	fd_set         sockfd_set;

	FD_ZERO(&sockfd_set);
	FD_SET(sockfd, &sockfd_set);
	block_time.tv_sec = TIMEOUT;      //time out 
	block_time.tv_usec = 0;

	//	printf("construct_ntp_packet\n");
	char content[48] = { 010, 0, 0, 0, 0, 0, 0, 0, 0 };
	int error;
	//printf("sendto\n");
	if (error = sendto(sockfd, content, 48, 0, (struct sockaddr *)server_addr, addr_len) < 0) {
		return (error);
	}

	if (select(sockfd + 1, &sockfd_set, NULL, NULL, &block_time) > 0) {
		if (error = recvfrom(sockfd, content, 256, 0, (struct sockaddr *)server_addr, (socklen_t *)&addr_len) < 0) {
			return (error);
		}
		else {
			memcpy(&temp, content + 40, 4);
			temp = (time_t)(ntohl(temp) - JAN_1970);
			timet = (time_t)temp;
			return timet;
		}
	}
	else {
		return(-99);
	}
	return(0);
}

int ntpdate() {
	// can be any timing server
	// you might have to change the IP if the server is no longer available
	char *hostname = (char *)"46.8.40.31";
	// ntp uses port 123
	int portno = 123;
	const int maxlen = 1024;
	// buffer for the socket request
	unsigned char msg[48] = { 010,0,0,0,0,0,0,0,0 };
	//struct in_addr ipaddr;
	struct protoent *proto; //
	struct sockaddr_in server_addr;
	int s; // socket
	long tmit; // the time -- This is a time_t sort of
			   // open a UDP socket
	proto = getprotobyname("udp");
	s = socket(PF_INET, SOCK_DGRAM, proto->p_proto);
	
	//here you can convert hostname to ipaddress if needed
	//$ipaddr = inet_aton($HOSTNAME);

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(hostname);
	server_addr.sin_port = htons(portno);
	tmit = get_ntp_time(s, &server_addr);

	return tmit;
}
/*
int ntpdate()
{
int                  sockfd, i;
struct tm            *net_tm;
struct sockaddr_in   addr;
char                 ip[16] = NTP_SERVER_1;
char                 date_buf[50];

SOCKET uiFdSocket;

WSADATA wsaData;

char szbuffer[1024] = "\0";

struct sockaddr_in stServerAddr;

struct sockaddr_in stClientAddr;

int iAddrlen = sizeof(sockaddr_in);

//printf("WSAStartup\n");

if (0 != WSAStartup(MAKEWORD(2, 1), &wsaData))
{

//printf("Winsock init failed!\r\n");

//WSACleanup();

return 0;

}

//printf("loop\n");
net_tm = (struct tm *)malloc(sizeof(struct tm));

memset(&addr, 0, sizeof(addr));
addr.sin_addr.s_addr = inet_addr(ip);
addr.sin_port = htons(123);

//printf("loop %d\n", i);

if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
//WSAGetLastError();
return 0;
}

//printf("get_ntp_time\n");
if (get_ntp_time(sockfd, &addr, net_tm) == 0) {
ConsolePrintColor(0, 255,0, "SUCCESS?");

return (int)net_tm;
}

closesocket(sockfd);


return (0);
}*/