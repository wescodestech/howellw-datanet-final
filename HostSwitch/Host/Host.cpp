// Host.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#define WIN32_LEAN_AND_MEAN


// Link with these libraries
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

// headers
#include <iostream>
#include <cstdlib>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <queue>
#include <string>
#include "header.h"

using namespace std;

#define BUFLEN 128
#define NPACK 10
#define PORT "0"
#define MAX_MSG_SIZE 84

/*Switch Info
This struct holds the switch info passed at the command line
and stored so the PHY_OUT queue can use it to send packs to the 
switch
*/
struct SwitchInfo {
	socklen_t addr_len;
	int packet_size;
	int max_packet_size;
	char IPAddress[1025];
	struct in_addr MyAddr;
}switchinfo;

/*ARPValue
This struct is used for the information
for the addresses used for this host and the
switch it connects two
*/
struct ARPValues {
	char* FakeIP;
	char* FakeMAC;
	char* RealIPSwitch;
	int RealPortSwitch;
	char* FakeMACSwitch;
	int UDPPort;
	char* RealIP;
};

/*ARP Table
This is the ARP table used to hold the values of the IP information of 
both the switch and host programs
*/
struct ARP {
	vector<ARPValues> *ARPTable ;
	int PacketCount;
} ARPTable;

struct ACK {
	bool SentACK;
	bool RecvACK;
}ACKValue;

/* UserInput Header
This is the new header used for queuing user input
to use before the fragmentation is calculated. This will then be placed into
the UserInput queue.
*/
typedef struct user_input{
	unsigned long DIP;
	unsigned long SIP;
	char* message;
	int delay;
}USER_INPUT_T;

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
	unsigned short type; // 0 for data, 1 for ACK
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

/*Queue Struct
This struct hold each of the queues and their lock key used in the program
the lock key tells whether a push or pop operation is being performed at the current time
*/
struct QueueMaster{
	bool InputLock;
	queue<user_input> *Input_Queue;

	bool IPoutLock;
	queue<ip_packet_header> *IP_out_Queue;

	bool LLCoutLock;
	queue<llc_pdu_header> *LLC_out_Queue;

	bool MACoutLock;
	queue<mac_frame_header> *MAC_out_Queue;
	
	bool IPinLock;
	queue<ip_packet_header> *IP_in_Queue;

	bool LLCinLock;
	queue<llc_pdu_header> *LLC_in_Queue;

	bool MACinLock;
	queue<mac_frame_header> *MAC_in_Queue;

	bool OutputLock;
	queue<user_input> *Output_Queue;
}QueueMaster;


/*LLC OUT THREAD
This thread will build an LLC Header and add it to the oldest IP
packet in the IP_Packet Queue. It will then store the new object in the
LLC_OUT_QUEUE
*/
DWORD _stdcall LLC_out_Thread (void* data){
	while(1){
		if(!QueueMaster.IP_out_Queue->empty()){
			Sleep(1000);
			//The queue has something in it, take it out and process it
			//char* ipheader;// = QueueMaster.IP_out_Queue->pop();
			//ipheader = new char[sizeof(struct ip_packet_header)];
			//memcpy(ipheader, &QueueMaster.IP_out_Queue->front(), sizeof(struct ip_packet_header));

			ip_packet_header iph = QueueMaster.IP_out_Queue->front();

			//check queue lock
			//while(QueueMaster.IPoutLock);
			//proceed 
				QueueMaster.IPoutLock = true;
				QueueMaster.IP_out_Queue->pop();
				QueueMaster.IPoutLock = false;

			//create llc header
			llc_pdu_header pdu = llc_pdu_header();
			pdu.DSAP = '0';
			pdu.LLCcontrol[0] = '0';
			pdu.LLCcontrol[1] = '0';
			pdu.SSAP = '0';
			pdu.iph = iph;

			//modify for queue
			/*char* sendBuf;
			int maxSize = sizeof(pdu) + sizeof(ipheader);
			sendBuf = new char [maxSize];
			memcpy(sendBuf, (void*)&pdu, sizeof(pdu));
			memcpy(&sendBuf[sizeof(pdu)], ipheader, sizeof(ipheader));*/

			//Add to queue
				while (QueueMaster.LLCoutLock);
				QueueMaster.LLCoutLock = true;
				QueueMaster.LLC_out_Queue->push(pdu);
				QueueMaster.LLCoutLock = false;
		}
		Sleep(100);
	}
	return 0;
}

/*MAC_OUT_THREAD
This MAC out thread will create the mac frame to be sent by the PHY_OUT thread
the mac object will contain the LLC header object and the MAC information needed to
send the MAC frame to the switch
*/
DWORD _stdcall MAC_out_Thread (void* data){
	while(1){
		if(!QueueMaster.LLC_out_Queue->empty()){
			//The queue has something in it, take it out and process it
			//char* LLCheader;// = QueueMaster.IP_out_Queue->pop();
			//LLCheader = new char[sizeof(QueueMaster.LLC_out_Queue->front())];
			//memcpy(LLCheader, &QueueMaster.LLC_out_Queue->front(), sizeof(QueueMaster.LLC_out_Queue->front()));

			llc_pdu_header lph = QueueMaster.LLC_out_Queue->front();

			//Check the LLC out lock
				while (QueueMaster.LLCoutLock);
				//Proceed
				QueueMaster.LLCoutLock = true;
				QueueMaster.LLC_out_Queue->pop();
				QueueMaster.LLCoutLock = false;
			
			//Create the MAC Header
			mac_frame_header mac = mac_frame_header();

			mac.llcpdu = lph;

			//Format the MAC Addr from the ARP Table to the MAC Frame requirements
			mac.DA[0] = ARPTable.ARPTable->at(0).FakeMACSwitch[0];
			mac.DA[1] = ARPTable.ARPTable->at(0).FakeMACSwitch[1];
			mac.DA[2] = ARPTable.ARPTable->at(0).FakeMACSwitch[3];
			mac.DA[3] = ARPTable.ARPTable->at(0).FakeMACSwitch[4];
			mac.DA[4] = ARPTable.ARPTable->at(0).FakeMACSwitch[6];
			mac.DA[5] = ARPTable.ARPTable->at(0).FakeMACSwitch[7];
			mac.DA[6] = ARPTable.ARPTable->at(0).FakeMACSwitch[9];
			mac.DA[7] = ARPTable.ARPTable->at(0).FakeMACSwitch[10];
			mac.DA[8] = ARPTable.ARPTable->at(0).FakeMACSwitch[12];
			mac.DA[9] = ARPTable.ARPTable->at(0).FakeMACSwitch[13];
			mac.DA[10] = ARPTable.ARPTable->at(0).FakeMACSwitch[15];
			mac.DA[11] = ARPTable.ARPTable->at(0).FakeMACSwitch[16];

			mac.SA[0] = ARPTable.ARPTable->at(0).FakeMAC[0];
			mac.SA[1] = ARPTable.ARPTable->at(0).FakeMAC[1];
			mac.SA[2] = ARPTable.ARPTable->at(0).FakeMAC[3];
			mac.SA[3] = ARPTable.ARPTable->at(0).FakeMAC[4];
			mac.SA[4] = ARPTable.ARPTable->at(0).FakeMAC[6];
			mac.SA[5] = ARPTable.ARPTable->at(0).FakeMAC[7];
			mac.SA[6] = ARPTable.ARPTable->at(0).FakeMAC[9];
			mac.SA[7] = ARPTable.ARPTable->at(0).FakeMAC[10];
			mac.SA[8] = ARPTable.ARPTable->at(0).FakeMAC[12];
			mac.SA[9] = ARPTable.ARPTable->at(0).FakeMAC[13];
			mac.SA[10] = ARPTable.ARPTable->at(0).FakeMAC[15];
			mac.SA[11] = ARPTable.ARPTable->at(0).FakeMAC[16];

			//Make the string the required length
			/*mac.length = sizeof(LLCheader);
			if(mac.length < 46){
				int diff = 46 - mac.length;
				for (int i = 0 ; i < diff; i++){
					strncat(LLCheader, "0", 1);
				}
				mac.length = 46;
				
			}*/
			
			//Set the preable values
			mac.PRE[0] = '0';
			mac.PRE[1] = '0';
			mac.PRE[2] = '0';
			mac.PRE[3] = '0';
			mac.PRE[4] = '0';
			mac.PRE[5] = '0';
			mac.PRE[6] = '0';

			//Set the SFD values
			mac.SFD = '0';

			//Set the frame check value
			short fcs = 0x00000000;

			//Print out info
			cout << "[MO] DA: " << ARPTable.ARPTable->at(0).FakeMACSwitch << endl << "[MO] SA: " << ARPTable.ARPTable->at(0).FakeMAC << endl << "[MO] CS: " << hex <<fcs << endl;
			cout << "size of fcs" << sizeof(fcs) << endl;
			cout << mac.SA << endl << mac.DA << endl;

			//Prepare for queue
			/*char* sendBuf;
			int maxSize = sizeof(LLCheader) + sizeof(mac) + sizeof(fcs);
			sendBuf = new char [maxSize];
			memcpy(sendBuf, (void*)&mac, sizeof(mac));
			memcpy(&sendBuf[sizeof(mac)], LLCheader, sizeof(LLCheader));
			int end = sizeof(mac) + sizeof(LLCheader);
			memcpy(&sendBuf[end], (void*)&fcs, sizeof(fcs));*/
			
			
			//Add to queue
				while (QueueMaster.MACoutLock);
				QueueMaster.MACoutLock = true;
				QueueMaster.MAC_out_Queue->push(mac);
				QueueMaster.MACoutLock = false;
		}
		Sleep(100);
	}
	return 0;
}

/*PHY_OUT_THREAD
This thread will send the completed mac frames that are in
the mac_out queue. These frames will be sent to the switch for 
forwarding
*/
DWORD _stdcall PHY_out_Thread (void* data){		
	//Setup 
	SOCKET clientSocket = *(SOCKET*)data;
	struct sockaddr_in SendToSocket;
	
	//Set IP information
	SendToSocket.sin_family = AF_INET; // IPv4  
	SendToSocket.sin_addr.s_addr = inet_addr(ARPTable.ARPTable->at(0).RealIPSwitch);
	SendToSocket.sin_port = htons( ARPTable.ARPTable->at(0).RealPortSwitch);

	int numbytes;

	header_t header;
	char message[MAX_MSG_SIZE+1];

	int seq = 0;
	char* send_buf; 
	int message_size;
	int rv;
	
	char buf[BUFLEN + 1];
	int i, j;
	i = 0;

	//Wait for MAC Frames
	while(1){
		if(!QueueMaster.MAC_out_Queue->empty()){
			//The queue has something in it, take it out and process it
			/*char* macframe;
			macframe = new char[sizeof(QueueMaster.MAC_out_Queue->front())];
			memcpy(macframe, &QueueMaster.MAC_out_Queue->front(), sizeof(QueueMaster.MAC_out_Queue->front()));*/

			mac_frame_header mfh = QueueMaster.MAC_out_Queue->front();
			
			//Check the Lock key
			while(QueueMaster.MACoutLock);
			//Proceed
			QueueMaster.MACoutLock = true;
			QueueMaster.MAC_out_Queue->pop();
			QueueMaster.MACoutLock = false;
			
			i++;

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
			memcpy(&buffer[50], &mfh.llcpdu.iph.type, 2);
			memcpy(&buffer[52], &mfh.llcpdu.iph.fragment_seq, 4);
			memcpy(&buffer[56], &mfh.llcpdu.iph.total_fragments, 4);
			memcpy(&buffer[60], &mfh.llcpdu.iph.message, 70);

			//Send the MAC Frame
			if ( (rv = sendto(clientSocket, buffer, 128, 0, (sockaddr*) &SendToSocket, switchinfo.addr_len))==-1)
			{
				cerr << "Cannot bind address to socket." << endl;	
				closesocket(clientSocket);
				WSACleanup();
				exit(0);
			}
			cout << "[PO] Frame #" << i << "sent (" << sizeof(buffer) << " bytes)." << endl;	
		}

		Sleep(100);
	}
	return 0;
}

/*PHY_IN_THREAD
This thread will wait for packets to come in. Once they come in, the packets will be placed
in the MAC_IN Queue.
*/
DWORD _stdcall PHY_in_Thread(void *data){		
	//Setup 
	int i = 0;
	SOCKET clientSocket = *(SOCKET*)data;
	struct sockaddr_in RecvFrom;
	char buf[BUFLEN+1];
	int numbytes;

	//Wait for Packets
	while(1){
		if ( (numbytes = recvfrom(clientSocket, buf, BUFLEN, 0, (sockaddr*) &RecvFrom, &switchinfo.addr_len))==-1)
		{
			cerr << "Could not receive datagram." << endl;
			closesocket(clientSocket);			
			WSACleanup();
			exit(0);
		}
		buf[numbytes] = '\0'; // append NULL to the end of the string

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
		memcpy( &mfh.llcpdu.iph.type,&buf[50], 2);
		memcpy( &mfh.llcpdu.iph.fragment_seq,&buf[52], 4);
		memcpy( &mfh.llcpdu.iph.total_fragments,&buf[56], 4);
		memcpy( &mfh.llcpdu.iph.message,&buf[60], 70);
		mfh.llcpdu.DSAP = '0';
		mfh.llcpdu.LLCcontrol[0] = '0';
		mfh.llcpdu.LLCcontrol[1] = '0';
		mfh.llcpdu.SSAP = '0';
		mfh.llcpdu.iph.TTL = 0;
		
		if(i != 0){
			//Check queue lock
			while (QueueMaster.MACinLock);
			QueueMaster.MACinLock = true;
			QueueMaster.MAC_in_Queue->push(mfh);
			QueueMaster.MACinLock = false;

			//Confirm with output
			cout << "[PI] Frame # "<< i << " received (" << numbytes << " bytes)." << endl;
		} 
		i++;
		Sleep(100);
	}
	return 0;
}

/*MAC_IN Thread
This thread will wait for mac frames to be received and placed in the MAC_IN queue
once in the queue, this thread will break off the MAC Frame header and forward the 
message to the LLC_in_Queue
*/
DWORD _stdcall MAC_in_Thread(void *data){
	//Wait for MACFrames
	while (1){
		//Check the Queue
		if(!QueueMaster.MAC_in_Queue->empty()){
			
			//Process the Header info
			mac_frame_header inmac = QueueMaster.MAC_in_Queue->front();
			
			//Output the MAC addresses in human readable form
			cout << "[MI] DA: ";
			for(int i=0; i < 12; i++){
				cout << inmac.DA[i];
				if(i%2 == 1){
					cout << ":";
				}
			}
			cout << endl;
			cout << "[MI] SA: ";
			for(int i=0; i < 12; i++){
				cout << inmac.SA[i];
				if(i%2 == 1){
					cout << ":";
				}
			}
			cout << endl;
			
			//Forward the rest of the packet to the next queue
			/*char* newbuf;
			newbuf = new char[sizeof(QueueMaster.MAC_in_Queue->front())];
			memcpy(newbuf, &QueueMaster.MAC_in_Queue->front()[sizeof(struct mac_frame_header)], 106);*/

			cout << "[MI] CS: 0x00000000" << endl;
			cout << "[MIIII] " << inmac.llcpdu.iph.type << endl;

			llc_pdu_header lpd = inmac.llcpdu;


			//Add the rest of the packet to the queue
			while(QueueMaster.LLCinLock);
				QueueMaster.LLCinLock = true;
				QueueMaster.LLC_in_Queue->push(lpd);
				QueueMaster.LLCinLock = false;
			
			//Remove processed mac frame from queue.
			while(QueueMaster.MACinLock);
				QueueMaster.MACinLock = true;
				QueueMaster.MAC_in_Queue->pop();
				QueueMaster.MACinLock = false;
			
		}
		Sleep(100);
	}
	return 0;
}

/*LLC_in_Thread
This thread is similar to the other two where it waits for packets 
to be placed in the LLC in queue and decomposes it to and IP packet
one decomposed, it places it in the IP in queue
*/
DWORD _stdcall LLC_in_Thread(void *data){
	//wait for packets
	while (1){
		if(!QueueMaster.LLC_in_Queue->empty()){
			//create header object
			llc_pdu_header inllc = QueueMaster.LLC_in_Queue->front();
			//memcpy(&inllc, QueueMaster.LLC_in_Queue->front(), sizeof(struct llc_pdu_header));
			
			//create the rest of the object
			/*char* newbuf;
			newbuf = new char[sizeof(QueueMaster.LLC_in_Queue->front())];
			memcpy(newbuf, &QueueMaster.LLC_in_Queue->front()[sizeof(struct llc_pdu_header)], 
				sizeof(QueueMaster.LLC_in_Queue->front()));*/

			ip_packet_header iph = inllc.iph;
			
			//Push the IP packet to its queue
			while(QueueMaster.IPinLock);
				QueueMaster.IPinLock = true;
				QueueMaster.IP_in_Queue->push(iph);
				QueueMaster.IPinLock = false;
			
			//remove the LLC packet from the LLC queue
			while(QueueMaster.LLCinLock);
				QueueMaster.LLCinLock = true;
				QueueMaster.LLC_in_Queue->pop();
				QueueMaster.LLCinLock = false;
			
		}
		Sleep(100);
	}
		Sleep(100);
	return 0;
}

/*OUTPUT_THREAD
This is the final step the in the process where the IP packet is 
disassembled and outputed to the screen and then the packet is removed
from the queue.
*/
DWORD _stdcall Output_Thread(void *data){
	//Wait for packet
	while (1){
		if(!QueueMaster.Output_Queue->empty()){

			user_input uin = QueueMaster.Output_Queue->front();
			
			//Pull IP addresses from the header object
			char dst[16];
			char src [16];
			inet_ntop(AF_INET, &uin.DIP, dst, 15);
			inet_ntop(AF_INET, &uin.SIP, src, 15);
			cout << "[OT] DST: " << dst <<  endl;
			cout << "[OT] SRC: " << src <<endl;
			
			string smsg = string(uin.message);
			cout << "[OT] MSG: " << smsg << endl;

			//remove packet from the queue.
			while(QueueMaster.OutputLock);
				QueueMaster.OutputLock = true;
				QueueMaster.Output_Queue->pop();
				QueueMaster.OutputLock = false;
		}
		Sleep(100);
	}
		Sleep(100);
	return 0;
}

DWORD _stdcall Network_out_Thread(void *data){

	//Wait for packet
	while (1){
		if(!QueueMaster.Input_Queue->empty() ){

			//Setup object
			user_input deque = QueueMaster.Input_Queue->front();
			int numFragments = (strlen(deque.message) / 70) + 1;
			
			//Create X number of IP Packets
			int i = 0;
			while (i < numFragments){
				
				ip_packet_header ippacket = ip_packet_header();
				if(i != numFragments - 1){
					//Create an IP packet with the item from the queue.
					ippacket.DIP = deque.DIP;
					ippacket.SIP = deque.SIP;
					ippacket.Version = 4;
					ippacket.type = i * 70;
					ippacket.fragment_seq = i;
					ippacket.total_fragments = numFragments;
					ippacket.TTL = 1;
					ippacket.length = 70;
					strncpy(ippacket.message, &deque.message[ippacket.type], 70);
					ippacket.message[70] = '\0';
				}else {
					ippacket.DIP = deque.DIP;
					ippacket.SIP = deque.SIP;
					ippacket.Version = 4;
					ippacket.type = i * 70;
					ippacket.fragment_seq = i;
					ippacket.total_fragments = numFragments;
					ippacket.TTL = 1;
					ippacket.length = strlen(deque.message) - ippacket.type;
					strncpy(ippacket.message, &deque.message[ippacket.type], ippacket.length);
					ippacket.message[70] = '\0';
				}

				//Print Out the Information//
					//Get IP Info and convert
					char DIP[16];
					char SIP[16];
					inet_ntop(AF_INET, &deque.DIP, DIP ,15);
					inet_ntop(AF_INET, &deque.SIP, SIP ,15);
					DIP[15] = '\0';
					SIP[15] = '\0';

					cout << dec <<"[NO] DST: " << DIP << endl << "[NO] Fragment " << ippacket.fragment_seq + 1 << " out of " << numFragments << endl << "[NO] Payload: " << ippacket.message << endl;

				while(QueueMaster.IPoutLock);
				QueueMaster.IPoutLock = true;
				QueueMaster.IP_out_Queue->push(ippacket);
				QueueMaster.IPoutLock = false;
				
				ACKValue.RecvACK = false;

				DWORD start_time = GetTickCount();
				DWORD curr_time;


				//STOP the program to wait for the ACK
				while(!ACKValue.RecvACK){
					curr_time = GetTickCount();

					//If We dont see the ack in 3 seconds, resend the packet
					if(curr_time - start_time > 3000) {
						break;
					}
				}
				//Send the next packet ONLY if we received the ACK.
				if(ACKValue.RecvACK) i++;
			}

			

			//remove packet from the queue.
			while(QueueMaster.InputLock);
				QueueMaster.InputLock = true;
				QueueMaster.Input_Queue->pop();
				QueueMaster.InputLock = false;
			
		}

		Sleep(100);
	}

	
	return 0;
}

DWORD _stdcall Network_in_Thread(void *data){
	//Object to use for the assembly of fragments
	user_input input;
	int size;
	char* message;
	
	//Wait for packet
	while (1){
		if(!QueueMaster.IP_in_Queue->empty()){

			//Setup
			ip_packet_header h = QueueMaster.IP_in_Queue->front();
			
			if (h.type == 1){

				//We receieved the ACK, Show this to the User.
				//Then allow The Network_OUT_Queue to continue
				cout << dec <<"[NI] ACK RECEIVED Fragment " << h.fragment_seq + 1 << " out of " << h.total_fragments << endl;
				ACKValue.RecvACK = true;

				
			}else if(h.fragment_seq == 0){
				//New series of packets
				message = new char[3100];
				strncpy(message, h.message, h.length);
				//Print Out the Information//
					//Get IP Info and convert
					char DIP[16];
					char SIP[16];
					inet_ntop(AF_INET, &h.DIP, DIP ,15);
					inet_ntop(AF_INET, &h.SIP, SIP ,15);
					DIP[15] = '\0';
					SIP[15] = '\0';
				//Print out info
				cout << dec <<"[NI] SRC: " << SIP << endl << "[NI] Fragment " << h.fragment_seq + 1 << " out of " << h.total_fragments << endl << "Payload: " << h.message << endl;

				//This packet is an ACK 
				//Get IP Info and reverse dst and src
				
				ip_packet_header ack = ip_packet_header();
				ack.DIP = h.SIP;
				ack.SIP = h.DIP;
				ack.fragment_seq = h.fragment_seq;
				ack.length = h.length;
				strcpy(ack.message, "                                                                   ");
				//message[70] = '\0';
				ack.total_fragments = h.total_fragments;
				ack.TTL = h.TTL;
				ack.Version = 4;
				ack.type = 1;

				//Push to IP Out Queue.
				QueueMaster.IP_out_Queue->push(ack);
				ACKValue.RecvACK = true;
				
			}else if(h.fragment_seq != h.total_fragments - 1 && h.fragment_seq != 0){
				//message = new char[h.total_fragments * 70];
				strcat(message, h.message);
				//Print Out the Information//
					//Get IP Info and convert
					char DIP[16];
					char SIP[16];
					inet_ntop(AF_INET, &h.DIP, DIP ,15);
					inet_ntop(AF_INET, &h.SIP, SIP ,15);
					DIP[15] = '\0';
					SIP[15] = '\0';
				//Print out info
				cout << dec <<"[NI] SRC: " << SIP << endl << "[NI] Fragment " << h.fragment_seq + 1 << " out of " << h.total_fragments << endl << "Payload: " << h.message << endl;

				//This packet is an ACK 
				//Get IP Info and reverse dst and src
				
				ip_packet_header ack = ip_packet_header();
				ack.DIP = h.SIP;
				ack.SIP = h.DIP;
				ack.fragment_seq = h.fragment_seq;
				ack.length = h.length;
				strcpy(ack.message, "                                                                   ");
				//message[70] = '\0';
				ack.total_fragments = h.total_fragments;
				ack.TTL = h.TTL;
				ack.Version = 4;
				ack.type = 1;

				//Push to IP Out Queue.
				QueueMaster.IP_out_Queue->push(ack);
				ACKValue.RecvACK = true;

			}else {
				//message = new char[h.total_fragments * 70];
				strcat(message, h.message);
				//We have copied the message set the null char
				//message[(h.total_fragments - 1 * 70) + h.length] = '\0';

				input = user_input();
				input.delay = 0;
				input.DIP = h.DIP;
				input.SIP = h.SIP;
				input.message = message;
				


				//Print Out the Information//
					//Get IP Info and convert
					char DIP[16];
					char SIP[16];
					inet_ntop(AF_INET, &h.DIP, DIP ,15);
					inet_ntop(AF_INET, &h.SIP, SIP ,15);
					DIP[15] = '\0';
					SIP[15] = '\0';
				//Print out info
				cout << dec <<"[NI] SRC: " << SIP << endl << "[NI] Fragment " << h.fragment_seq + 1 << " out of " << h.total_fragments << endl << "Payload: " << h.message << endl;

				//This packet is an ACK 
				//Get IP Info and reverse dst and src
				
				ip_packet_header ack = ip_packet_header();
				ack.DIP = h.SIP;
				ack.SIP = h.DIP;
				ack.fragment_seq = h.fragment_seq;
				ack.length = h.length;
				strcpy(ack.message, "                                                                   ");
				//message[70] = '\0';
				ack.total_fragments = h.total_fragments;
				ack.TTL = h.TTL;
				ack.Version = 4;
				ack.type = 1;

				//Push to IP Out Queue.
				QueueMaster.IP_out_Queue->push(ack);
				ACKValue.RecvACK = true;

				//Send to Queue ONLY if we have recieve all the packets
				//Since we are in this part of the if, we are at the last packet
				while(QueueMaster.OutputLock);
					QueueMaster.OutputLock = true;
					QueueMaster.Output_Queue->push(input);
					QueueMaster.OutputLock = false;

			}
			
			//remove packet from the queue.
			while(QueueMaster.IPinLock);
				QueueMaster.IPinLock = true;
				QueueMaster.IP_in_Queue->pop();
				QueueMaster.IPinLock = false;
			
		}

		Sleep(100);
	}
	return 0;
}






int main(int argc, char* argv[])
{
	//WINSOCK SETUP
	WSADATA w;
	SOCKET socketfd;
	struct addrinfo hints, *servinfo, *p;

	char* server_ip_addr;
	int server_port;
	struct sockaddr_in server_addr, si_recvfrom;

	socklen_t addr_len;

	int i;
	int j;
	int rv; 

    char buf[BUFLEN+1];
	int numbytes;

	// Used for the original resistration packet
	char* send_buf; 
	int message_size;

	// parse the parameters

	if( argc != 7)
	{
		cout << "Usage: " << argv[0] << " server_ip_addr server_port client_name" << endl;
		return 0;
	}

	//Pull Params from cmd line
	server_ip_addr = argv[4];
	server_port = atoi( argv[5]);

	ARPValues cmdline = ARPValues();
	cmdline.FakeIP = argv[1];
	cmdline.FakeMAC = argv[2];
	cmdline.UDPPort = atoi(argv[3]);
	cmdline.RealIPSwitch = argv[4];
	cmdline.RealPortSwitch = atoi(argv[5]);
	cmdline.FakeMACSwitch = argv[6];

	//Create ARP Table
	ARPTable.ARPTable = new vector<ARPValues>();
	ARPTable.ARPTable->push_back(cmdline);

	// Initialize Winsock
	if (WSAStartup(MAKEWORD(2,2), &w) != 0)		
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
	if ((rv = getaddrinfo(NULL, argv[3] , &hints, &servinfo)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        exit(1);
    }

	// loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) 
	{
        if ((socketfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
             cerr << "socket" << endl;
            continue;
        }

        if (bind(socketfd, p->ai_addr, p->ai_addrlen) == -1) {
            closesocket(socketfd);
            cerr << " bind" << endl;
            continue;
        }

        break;
    }

	
	if (p == NULL) 
	{
        cerr << "Failed to bind socket" << endl;
        exit(2);
    }

	freeaddrinfo(servinfo);

	// We are not showing the IP address/port of the client here, check server for the example
	//switchinfo.IPAddress = new char [1024];
	gethostname(switchinfo.IPAddress, sizeof(switchinfo.IPAddress));
	hostent *hp;
	hp = gethostbyname(switchinfo.IPAddress);
	if(hp == NULL){

	}
	//struct in_addr myinfo;
	memcpy(&switchinfo.MyAddr, hp->h_addr_list[0], sizeof(struct in_addr));
	cout << "HERE IS MY IP ADDR " << inet_ntoa(switchinfo.MyAddr) << endl;
	


	// set server address
	server_addr.sin_family = AF_INET; // IPv4  
	server_addr.sin_addr.s_addr = inet_addr(ARPTable.ARPTable->at(0).RealIPSwitch);
	server_addr.sin_port = htons(ARPTable.ARPTable->at(0).RealPortSwitch);
	

	// find the max packet size (size of the header + message)

	switchinfo.max_packet_size = sizeof( header_t) + MAX_MSG_SIZE;

	// create send_buf (to store the packet)

	send_buf = new char[switchinfo.max_packet_size];


	addr_len = sizeof server_addr;
	switchinfo.addr_len = sizeof server_addr;


	//Registration of host
	//create Datagram to send for registration.
		char* regpack;
		regpack = new char [52];
		strncpy(regpack, "REG", 3);
		strncpy(&regpack[3], ARPTable.ARPTable->at(0).FakeIP, 15);

		//Pull MAC Info
		strncpy(&regpack[18], &ARPTable.ARPTable->at(0).FakeMAC[0], 1);
		regpack[18] = ARPTable.ARPTable->at(0).FakeMAC[0];
		regpack[19] = ARPTable.ARPTable->at(0).FakeMAC[1];
		regpack[20] = ARPTable.ARPTable->at(0).FakeMAC[3];
		regpack[21] = ARPTable.ARPTable->at(0).FakeMAC[4];
		regpack[22] = ARPTable.ARPTable->at(0).FakeMAC[6];
		regpack[23] = ARPTable.ARPTable->at(0).FakeMAC[7];
		regpack[24] = ARPTable.ARPTable->at(0).FakeMAC[9];
		regpack[25] = ARPTable.ARPTable->at(0).FakeMAC[10];
		regpack[26] = ARPTable.ARPTable->at(0).FakeMAC[12];
		regpack[27] = ARPTable.ARPTable->at(0).FakeMAC[13];
		regpack[28] = ARPTable.ARPTable->at(0).FakeMAC[15];
		regpack[29] = ARPTable.ARPTable->at(0).FakeMAC[16];

		//Pull UDP Info
		strncpy(&regpack[30], inet_ntoa(switchinfo.MyAddr), 15);
		char udpstr[6];
		itoa(ARPTable.ARPTable->at(0).UDPPort, udpstr, 10);
		strncpy(&regpack[45], udpstr, 5);
		strncpy(&regpack[50], " ", 1);

		//Send registration packet
		if ( (rv = sendto(socketfd, regpack, 55, 0, (sockaddr*) &server_addr, switchinfo.addr_len))==-1)
		{
			cerr << "Cannot bind address to socket." << endl;	
			closesocket(socketfd);
			WSACleanup();
			exit(0);
		}
		cout << "Packet size is " << switchinfo.packet_size << "-byte, "<< rv << " bytes sent!" << endl << endl;

		Sleep(1000);

	//New up the queues
	QueueMaster.IPinLock = false;
	QueueMaster.LLCinLock = false;
	QueueMaster.MACinLock = false;
	QueueMaster.IPoutLock = false;
	QueueMaster.LLCoutLock = false;
	QueueMaster.MACoutLock = false;
	QueueMaster.InputLock = false;
	QueueMaster.OutputLock = false;
	QueueMaster.IP_in_Queue = new queue<ip_packet_header>();
	QueueMaster.LLC_in_Queue = new queue<llc_pdu_header>();
	QueueMaster.MAC_in_Queue = new queue<mac_frame_header>();
	QueueMaster.IP_out_Queue = new queue<ip_packet_header>();
	QueueMaster.LLC_out_Queue = new queue<llc_pdu_header>();
	QueueMaster.MAC_out_Queue = new queue<mac_frame_header>();
	QueueMaster.Input_Queue = new queue<user_input>();
	QueueMaster.Output_Queue = new queue<user_input>();
	ACKValue.RecvACK = true;
	ACKValue.SentACK = true;

	/*	This is where we will spawn the threads for the program...
		This main thread will also serve as the Input_Thread and take in the text from
		the command line.
		Thus The following threads will be spawned
		LLC_out_Thread
		MAC_out_Thread
		PHY_out_Thread
		PHY_in_Thread
		MAC_in_Thread
		LLC_in_Thread
		Output_Thread 
	*/
	CreateThread(NULL, 0, LLC_out_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, MAC_out_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0 , PHY_out_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, PHY_in_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, LLC_in_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, MAC_in_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, Output_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, Network_out_Thread, (void*)&socketfd, 0, NULL);
	CreateThread(NULL, 0, Network_in_Thread, (void*)&socketfd, 0, NULL);

	/*
		This Part of the Main Thread will serve as the Input_Thread
	*/
	while(1){

		//Wait for user input
		cin.getline(buf, BUFLEN+1);
		char* lines;
		lines = strtok(buf, " ");

		//Parse User Input
		char* delay = lines;
		lines = strtok(NULL, " ");
		char* IP = lines;
		lines = strtok(NULL, " ");
		char* NumBytes = lines;
		lines = strtok(NULL, "");
		char* Seed = lines;
		
			//Queue it up!
			//Create an IP Header
			//ip_packet_header inheader = ip_packet_header();
			user_input uinput = user_input();
			inet_pton(AF_INET, IP, &uinput.DIP);			
			char msgs[16];			
			inet_pton(AF_INET, ARPTable.ARPTable->at(0).FakeIP, &uinput.SIP);
			uinput.delay = atoi(delay);
		
			int SeedInt = atoi(Seed);
			int MessageSize = atoi(NumBytes);
			//Create Message to send
			//Creat buffer for queue
			char* sendBuf = new char[MessageSize + 1];
			for(int i = 0; i < MessageSize; i++){
				sendBuf[i] = (((i/10)+SeedInt)%10) + '0';
			}
			sendBuf[MessageSize] = '\0';

			uinput.message = sendBuf;

			//Add to queue
			Sleep(atoi(delay));

			

			if(QueueMaster.InputLock == false){
				QueueMaster.InputLock = true;
				QueueMaster.Input_Queue->push(uinput);
				QueueMaster.InputLock = true;
			}
			
			char DIP[16];
			char SIP[16];
			inet_ntop(AF_INET, &QueueMaster.Input_Queue->front().DIP, DIP ,15);
			inet_ntop(AF_INET, &QueueMaster.Input_Queue->front().SIP, SIP ,15);
			DIP[15] = '\0';
			SIP[15] = '\0';

			cout << "User Input Thread Test Check" << endl;
			cout << DIP << endl << SIP << endl << &QueueMaster.Input_Queue->front().delay << endl << &QueueMaster.Input_Queue->front().message << endl;
			cout << "END User Input Thread Test Check" << endl;
		
	}
	
	//Cleanup
    closesocket(socketfd);
	WSACleanup();
    return 0;
}

