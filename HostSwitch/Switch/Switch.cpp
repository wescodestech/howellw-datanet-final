#include "stdafx.h"

// Link with these libraries
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


// headers
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <inaddr.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "header.h"

using namespace std;

#define BUFLEN 128 // enough to hold [header] + [message]
#define NPACK 10
#define PORT "0" // OS kernel will choose a port for you if set to 0

/*ARP Values
Struct to be used in ARP table
*/
struct ARPValues {
	char FakeIP[16];
	char FakeMAC[13];
	char RealIP[16];
	int UDPPort;
};

/*ARP Table
this is the ARP table used to store all the IP information
about connected host
*/
struct ARP {
	vector<ARPValues> *ARPTable ;
	int PacketCount;
} ARPTable;

/*IP Packet Header
This is the IP packet header 
this struct holds the values used to make the header object 
for the initial IP Packet
*/
typedef struct ip_packet_header{
	unsigned int Version; //4-byte numberic, value of 4
	unsigned int length;
	unsigned int fragment_seq;
	unsigned int total_fragments;
	unsigned short fragment_offset;
	unsigned short TTL;//time to live
	unsigned long DIP;
	unsigned long SIP;
	char message[71];
}IP_PACKET_HEADER_T;

/*LLC PDU Header
This header stores the information for the second step thread
this is information will eventually be added to an ip packet
*/
typedef struct llc_pdu_header{
	unsigned char DSAP;
	unsigned char SSAP;
	unsigned char LLCcontrol[2];
	ip_packet_header iph;
}LLC_PDU_HEADER_T;

/*MAC Frame Header
This mac frame header will store the MAC information used
for the MAC frames that will eventually be sent
*/
typedef struct mac_frame_header{
	char PRE[7];
	char SFD;
	char DA[12];
	char SA[12];
	char IP[15];
	short length;
	llc_pdu_header llcpdu;
}MAC_FRAME_HEADER_T;

int main(int argc, char* argv[])
{
	//WINSOCK setup
	WSADATA w;							
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr, fwd_addr;
	struct sockaddr_in sin;
	struct sockaddr_in fwd;
	socklen_t addr_len;
	socklen_t fwd_len;

	//LOCAL information
	char* LocalMac;
	char* LocalPort;
	char* FIPSwitch;
	char* RIProuter;
	char* RealPortRouter;
	char* FIPRouter;
	char* FMacRouter;
	char* NewSwitch;

	hostent* hp;
	struct in_addr my_addr;
	int my_port;
	char my_hostname[NI_MAXHOST];
	
	//Socket to use
	SOCKET socketfd;
	
	int numbytes;
	int i;
    char buf[BUFLEN+1];
	char host[NI_MAXHOST], port[NI_MAXSERV]; // to hold the address and port of the remote host 
	int rv; // return value

	header_t header; // to store the header
	char message[MAX_MSG_SIZE+1]; // for the message

	//Parse the Params
	if(argc !=9){
		cout <<"Execute like: Switch [Fake Mac addr] [Real Port number]"<<endl;
	}
	LocalMac = argv[3];
	LocalPort = argv[1];
	FIPSwitch = argv[2];
	RIProuter = argv[4];
	RealPortRouter = argv[5];
	FIPRouter = argv[6];
	FMacRouter = argv[7];
	NewSwitch = argv[8];


	// Initialize Winsock
	if (WSAStartup(MAKEWORD(2, 2), &w) != 0)	
	{
		cerr << "Could not open Windows connection." << endl;	
		exit(1);
	}

	// Open a (UDP) datagram socket
	socketfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socketfd == INVALID_SOCKET)
	{
		cerr <<  "Could not create socket." << endl;	
		WSACleanup();
		exit(1);
	}

	// Clear out hints struct
	ZeroMemory( &hints, sizeof(hints) );
	
	// Set family and port
	hints.ai_family = AF_INET;		// set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
	
	// get address info
	if ((rv = getaddrinfo(NULL, LocalPort, &hints, &servinfo)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        exit(1);
    }

	// loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
	{
        if ((socketfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
            cerr << "server: socket" << endl;
            continue;
        }

        if (bind(socketfd, p->ai_addr, p->ai_addrlen) == -1)
		{
            closesocket(socketfd);
            cerr << "server: bind" << endl;
            continue;
        }
        break;
    }
	if (p == NULL) 
	{
        cerr << "server: failed to bind socket" << endl;
		WSACleanup();
        exit(2);
    }

	freeaddrinfo(servinfo);

	// use getsockname to get the port number from socketfd

	addr_len = sizeof sin;

	if( getsockname( socketfd, (sockaddr *)&sin, &addr_len) != 0 )
	{
		cerr << "server: getsockname" << endl;
		WSACleanup();
        exit(1);
	}

	// The IP address is 0.0.0.0 (INADDR_ANY)

	my_port = ntohs(sin.sin_port);

	cout << "socketfd is running at " << inet_ntoa( sin.sin_addr) << ":" << my_port << endl;

	// We can use the following method to get the IP address of local host
	gethostname( my_hostname, sizeof(my_hostname));
	hp = gethostbyname( my_hostname);
	if( hp == NULL)
	{
		cout << "server: gethostbyname: " << errno<< endl;
		WSACleanup();
		exit(1);
	}
	cout << "socketfd is running at... " ;
	for (int i = 0; hp->h_addr_list[i] != 0; i++)
	{
		struct in_addr addr;
		memcpy(&my_addr, hp->h_addr_list[i], sizeof(struct in_addr));
		cout <<  inet_ntoa(my_addr) ;
	}
	cout << ":" << my_port << endl;

	cout << "Waiting for UDP packets..." << endl;

	//Take Fake MAC Address and place into ARP Table for the switch program.
	//This is so the threads can see this information and check to see if the messages
	//have the MAC address of the switch and forward it to the correct host
	
	//Convert MAC Address to 12 char number
	char newMac [13];
	newMac[0] = LocalMac[0];
	newMac[1] = LocalMac[1];
	newMac[2] = LocalMac[3];
	newMac[3] = LocalMac[4];
	newMac[4] = LocalMac[6];
	newMac[5] = LocalMac[7];
	newMac[6] = LocalMac[9];
	newMac[7] = LocalMac[10];
	newMac[8] = LocalMac[12];
	newMac[9] = LocalMac[13];
	newMac[10] = LocalMac[15];
	newMac[11] = LocalMac[16];
	newMac[12] = '\0';

	//Create and ARP table entry
	ARPTable.ARPTable = new vector<ARPValues> ();
	ARPValues switchInfo =  ARPValues();
	strcpy(switchInfo.FakeMAC, newMac);
	//switchInfo.FakeMAC = newMac;
	//switchInfo.RealIP = inet_ntoa(my_addr);
	strcpy(switchInfo.RealIP, inet_ntoa(my_addr));
	switchInfo.UDPPort = my_port;
	ARPTable.ARPTable->push_back(switchInfo);
	ARPTable.PacketCount = 0; //Set the counter of the number of packets to 0
	cout << "Converted MAC " << newMac << endl;

	ARPTable.PacketCount = 0; // We will keep track of the number of Datagram packets are receieved.

	// receive packets and send ACKs
	addr_len = sizeof their_addr;


	if(NewSwitch[0] == 'y' || NewSwitch[0] == 'Y'){
		fwd.sin_family = AF_INET;						
		fwd.sin_addr.s_addr = inet_addr(RIProuter);
		fwd.sin_port = htons(atoi(RealPortRouter)+1);
		fwd_len = sizeof fwd;
		
		string regMessage = "DVRP[" + string(RIProuter) + ":" + string(LocalPort) + " " + string(FIPRouter) +"/24 | " + string(FIPSwitch) + "/24 0]";
		cout << regMessage << endl;
		if (sendto(socketfd, regMessage.c_str(), BUFLEN, 0, (sockaddr*) &fwd, fwd_len)==-1)
			{
				cerr << "Cannot bind address to socket." << endl;	
				closesocket(socketfd);
				WSACleanup();
				exit(0);
			}

	}

    while(1){

		/* receive the packet */

		if ( (numbytes = recvfrom(socketfd, buf, BUFLEN, 0, (sockaddr*) &their_addr, &addr_len))==-1)
		{
			cerr <<  "Could not receive datagram." << WSAGetLastError() << endl;
			closesocket(socketfd);			
			WSACleanup();
			exit(0);
		}
		buf[numbytes] = '\0'; // append NULL to the end of the string

		// call getnameinfo to get the IP address and port number of the remote host (NI_NUMERICHOST | NI_NUMERICSERV)
		if ( (rv = getnameinfo( (struct sockaddr *)&their_addr, sizeof (struct sockaddr), host, NI_MAXHOST, port, NI_MAXSERV,  NI_NUMERICHOST | NI_NUMERICSERV))
			!= 0)
		{
			cerr << "getnameinfo: " << WSAGetLastError() << endl;
			WSACleanup();
			exit(1);
		}
		
		cout << numbytes << " bytes received packet from " << host << ":" << port << endl;

		//Check for registration packet
		if (buf[0] == 'R'){
			//Registration Packet
			char FIP[16];
			for(int i = 3; i <= 17; i++){
				if(buf[i] == ' '){
					FIP[ i - 3] = '\0';
					break;
				}
				FIP[i-3] = buf[i];
			}
			FIP[15] = '\0';
			cout << FIP << endl;

			char FMAC[13];
			for(int i = 18; i <= 29; i++){
				if(buf[i] == ' '){
					FMAC[ i - 18] = '\0';
					break;
				}
				FMAC[i-18] = buf[i];
			}
			FMAC[12] = '\0';
			//cout << FMAC << endl;

			char RIP[16];
			for(int i = 30; i <= 44; i++){
				if(buf[i] == ' '){
					RIP[ i - 30] = '\0';
					break;
				}
				RIP[i-30] = buf[i];
			}
			RIP[15]='\0';
			//cout << RIP << endl;

			char RPort[6];
			for(int i = 45; i <= 49; i++){
				if(buf[i] == ' '){
					RPort[ i - 45] = '\0';
					break;
				}
				RPort[i-45] = buf[i];
			}
			RPort[5] = '\0';

			//Create new entry in ARP Table
			ARPValues reg = ARPValues();
			//reg.FakeIP = FIP;
			strcpy(reg.FakeIP, FIP);
			//reg.FakeMAC = FMAC;
			strcpy(reg.FakeMAC, FMAC);
			//reg.RealIP = RIP;
			strcpy(reg.RealIP, RIP);
			reg.UDPPort = atoi(RPort);
			
			ARPTable.ARPTable->push_back(reg);

			cout << "ARP TABLE VALUES:" << endl;
			for(int i = 0; i < ARPTable.ARPTable->size(); i++){
				if(i > 0){
					cout << ARPTable.ARPTable->at(i).RealIP << " " << ARPTable.ARPTable->at(i).UDPPort << " " << ARPTable.ARPTable->at(i).FakeIP << " " << ARPTable.ARPTable->at(i).FakeMAC << endl;
				}else{
					cout << ARPTable.ARPTable->at(i).RealIP << " " << ARPTable.ARPTable->at(i).UDPPort << endl;
				}
			}

			//Send ACK
			sprintf( buf, "ACK Registration for MAC Address %s", reg.FakeMAC);

			// Send ACK
			if (sendto(socketfd, buf, BUFLEN, 0, (sockaddr*) &their_addr, addr_len)==-1)
			{
				cerr << "Cannot bind address to socket." << endl;	
				closesocket(socketfd);
				WSACleanup();
				exit(0);
			}
			//Output on the switch
			cout << "[REG] F IP: " << reg.FakeIP << endl;
			cout << "[REG] FMAC: ";
			for (int i=0; i < 12; i++){
				cout << reg.FakeMAC[i];
				if(i == 11) break;
				if(i % 2 == 1){
					cout << ":";
				}
			
			}
			cout << endl;
			cout <<"[REG] R IP: " << reg.RealIP << endl;
			cout <<"[REG] PORT: " << reg.UDPPort << endl;
		} else {
			//If we are here, we are seeing a regular Data Packet as A MAC FRAME
			//Extract IP Addr and MAC Addr
			
			//Generate K to drop a random packet

			int K;
			srand (time(NULL));
			K = rand() % 100;

			
			//Increment the counter
			ARPTable.PacketCount ++;
			
			//Info to extract from message
			mac_frame_header mfh = mac_frame_header();
			memcpy(&mfh.PRE,&buf,  7);
			memcpy( &mfh.SFD,&buf[7], 1);
			memcpy( &mfh.DA,&buf[8], 12);
			memcpy( &mfh.SA,&buf[20], 12);
			memcpy( &mfh.length,&buf[32], 2);
			memcpy( &mfh.llcpdu.iph.DIP,&buf[34], 4);
			memcpy( &mfh.llcpdu.iph.SIP,&buf[38], 4);
			memcpy( &mfh.llcpdu.iph.Version,&buf[42], 4);
			memcpy( &mfh.llcpdu.iph.length,&buf[46], 4);
			memcpy( &mfh.llcpdu.iph.fragment_offset,&buf[50], 2);
			memcpy( &mfh.llcpdu.iph.fragment_seq,&buf[52], 4);
			memcpy( &mfh.llcpdu.iph.total_fragments,&buf[56], 4);
			memcpy( &mfh.llcpdu.iph.message,&buf[60], 70);
			mfh.llcpdu.DSAP = '0';
			mfh.llcpdu.LLCcontrol[0] = '0';
			mfh.llcpdu.LLCcontrol[1] = '0';
			mfh.llcpdu.SSAP = '0';
			mfh.llcpdu.iph.TTL = 0;

			char DIP[16];
			char SIP[16];
			inet_ntop(AF_INET, &mfh.llcpdu.iph.DIP, DIP ,15);
			inet_ntop(AF_INET, &mfh.llcpdu.iph.SIP, SIP ,15);
			DIP[15] = '\0';
			SIP[15] = '\0';
			
			char IPAddrRecv[16];
			char MACAddrRecv[13];
			strncpy(IPAddrRecv, &buf[34], 15);
			IPAddrRecv[15] = '\0';
			strncpy(MACAddrRecv, &buf[8], 12);
			MACAddrRecv[12]='\0';
			char MACAddrChange[13];

			if(K > 4 || mfh.llcpdu.iph.fragment_offset == 1){

			bool flag = false;
			//Check to see if MAC Addr is the same as the switch, if so, then change it to match the IP Addr
			if (true){

				for(int i = 1; i < ARPTable.ARPTable->size(); i++){
					cout << ARPTable.ARPTable->at(i).FakeIP << endl;
					//Compare the DIP with the ARP Table
					if ((strncmp(DIP, ARPTable.ARPTable->at(i).FakeIP,  15)) == 0){
						strcpy(mfh.DA, ARPTable.ARPTable->at(i).FakeMAC);
						MACAddrChange[12] = '\0';
						
						//Update the FWD with the correct information
						fwd.sin_family = AF_INET;						
						fwd.sin_addr.s_addr = inet_addr(ARPTable.ARPTable->at(i).RealIP);
						fwd.sin_port = htons(ARPTable.ARPTable->at(i).UDPPort);
						fwd_len = sizeof fwd;
						cout << "DIP:   " << DIP << endl;
						cout << "DEST:  " << ARPTable.ARPTable->at(i).FakeIP << endl;
						cout << "PORT:  " << ARPTable.ARPTable->at(i).UDPPort << endl;
						cout << "INDEX  " << i << endl;
						cout << "Reset Forward" << endl;
						flag = true;
						break;
					}

				} 

				//If the DIP was not found, forward to the router
				if (!flag){
					mfh.DA[0] = FMacRouter[0];
					mfh.DA[1] = FMacRouter[1];
					mfh.DA[2] = FMacRouter[3];
					mfh.DA[3] = FMacRouter[4];
					mfh.DA[4] = FMacRouter[6];
					mfh.DA[5] = FMacRouter[7];
					mfh.DA[6] = FMacRouter[9];
					mfh.DA[7] = FMacRouter[10];
					mfh.DA[8] = FMacRouter[12];
					mfh.DA[9] = FMacRouter[13];
					mfh.DA[10] = FMacRouter[15];
					mfh.DA[11] = FMacRouter[16];
					//Set the router's information
					fwd.sin_family = AF_INET;

					char ripr[16];
					strncpy(ripr, RIProuter, 15);
					ripr[15] = '\0';
					char rpr[6];
					cout << "ROUTER PORT" << endl;
					strncpy(rpr, RealPortRouter, 5);
					rpr[5] = '\0';
					cout << atoi(rpr) << endl;
					fwd.sin_addr.s_addr = inet_addr(ripr);
					fwd.sin_port = htons(atoi(rpr));
					fwd_len = sizeof fwd;

				}

			} //else strncpy(MACAddrChange, MACAddrRecv,12);
			MACAddrChange[12] = '\0';
			
			//Change the MAC Frame
			/*for(int i = 8; i <= 19; i++){
				buf[i] = MACAddrRecv[i - 8];
			}*/

			//Researlize Mac Frame
			//Searlized the Mac Frame
			char* buffer = new char[156];
			//Parse the macframe info
			memcpy(buffer, &mfh.PRE, 7);
			memcpy(&buffer[7], &mfh.SFD, 1);
			memcpy(&buffer[8], &mfh.DA, 12);
			memcpy(&buffer[20], &mfh.SA, 12);
			memcpy(&buffer[32], &mfh.length, 2);
			memcpy(&buffer[34], &mfh.llcpdu.iph.DIP, 4);
			memcpy(&buffer[38], &mfh.llcpdu.iph.SIP, 4);
			memcpy(&buffer[42], &mfh.llcpdu.iph.Version, 4);
			memcpy(&buffer[46], &mfh.llcpdu.iph.length, 4);
			memcpy(&buffer[50], &mfh.llcpdu.iph.fragment_offset, 2);
			memcpy(&buffer[52], &mfh.llcpdu.iph.fragment_seq, 4);
			memcpy(&buffer[56], &mfh.llcpdu.iph.total_fragments, 4);
			memcpy(&buffer[60], &mfh.llcpdu.iph.message, 70);

			//Lookup Real IP Address and set the IP and port address
			for(int i = 1; i < ARPTable.ARPTable->size(); i++){
				if(ARPTable.ARPTable->at(i).FakeIP == IPAddrRecv){
					
				}
			}
			//Lookup Source IP Address from Source
			char MACAddrSRC[13]; 
			strncpy(MACAddrSRC, &buf[20], 12);
			MACAddrSRC[12] = '\0';
			char IPAddrSRC[16];

			//Forward the Frame
			if (sendto(socketfd, buffer, BUFLEN, 0, (sockaddr*) &fwd, fwd_len)==-1)
			{
				
				cout << "Unable To Forward Sending Back"<< endl;
				cout <<"[SW] Frame " << ARPTable.PacketCount << " received (" << numbytes << " bytes)." << endl;
				cout <<"[SW] DST: " << DIP<< "/";
				for (int i=0; i < 12; i++){
					cout << MACAddrRecv[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				}
				cout << endl;
				cout <<"[SW] SRC: " << SIP <<   "/"; 
				for (int i=0; i < 12; i++){
					cout << MACAddrSRC[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				} cout << endl;
				
				fwd.sin_family = AF_INET;						
				fwd.sin_addr.s_addr = inet_addr(ARPTable.ARPTable->at(1).RealIP);
				fwd.sin_port = htons(ARPTable.ARPTable->at(1).UDPPort);
				fwd_len = sizeof fwd;

				if(sendto(socketfd, buf, BUFLEN, 0, (sockaddr*) &fwd, fwd_len) == -1){
					cout << "F ERROR" << endl;
				}

			} else {
				//It sent successfully Update screen

				char DIP1[16];
				char SIP1[16];
				inet_ntop(AF_INET, &mfh.llcpdu.iph.DIP, DIP1 ,15);
				inet_ntop(AF_INET, &mfh.llcpdu.iph.SIP, SIP1 ,15);
				DIP1[15] = '\0';
				SIP1[15] = '\0';
				
				cout <<"[SW] Frame " << ARPTable.PacketCount << " received (" << numbytes << " bytes)." << endl;
				cout <<"[SW] DST: " << DIP1 << "/";
				for (int i=0; i < 12; i++){
					cout << mfh.DA[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				}
				cout << endl;
				cout <<"[SW] SRC: " << SIP1 << "/"; 
				for (int i=0; i < 12; i++){
					cout << MACAddrSRC[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				}
				cout<< endl;
				cout << "[SW] Next Hop: " << SIP1 << endl;
				cout << "[SW] Fragment: " << mfh.llcpdu.iph.fragment_seq + 1 << " out of " << mfh.llcpdu.iph.total_fragments << endl;
				cout << "[SW] K: " << K << " (Not Dropped)" << endl;

			}
		}else {
			char DIP1[16];
				char SIP1[16];
				inet_ntop(AF_INET, &mfh.llcpdu.iph.DIP, DIP1 ,15);
				inet_ntop(AF_INET, &mfh.llcpdu.iph.SIP, SIP1 ,15);
				DIP1[15] = '\0';
				SIP1[15] = '\0';
				
				cout <<"[SW] Frame " << ARPTable.PacketCount << " received (" << numbytes << " bytes)." << endl;
				cout <<"[SW] DST: " << DIP1 << "/";
				for (int i=0; i < 12; i++){
					cout << mfh.DA[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				}
				cout << endl;
				cout <<"[SW] SRC: " << SIP1 << "/"; 
				for (int i=0; i < 12; i++){
					cout << mfh.SA[i];
					if(i == 11) break;
					if(i % 2 == 1){
						cout << ":";
					}
			
				}
				cout<< endl;
				cout << "[SW] Next Hop: " << SIP1 << endl;
				cout << "[SW] Fragment: " << mfh.llcpdu.iph.fragment_seq + 1 << " out of " << mfh.llcpdu.iph.total_fragments << endl;
				cout << "[SW] K: " << K << " (Dropped)" << endl;
			}
		}
    }

	closesocket(socketfd);
	WSACleanup();
    return 0;
}