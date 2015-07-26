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
#include <fstream>
#include <string>
#include "header.h"
using namespace std;

#define BUFLEN 128 // enough to hold [header] + [message]
#define BUFLENDV 1000
#define NPACK 10
#define PORT "0" // OS kernel will choose a port for you if set to 0

// ARP Values
// Struct to be used in ARP table
struct ARPValues
{
    char FakeIP[16];
    char FakeMAC[13];
    char RealIP[16];
    int UDPPort;
};

// Routing Info
// Struct to be used for the Routing Table
struct RoutingInfo
{
    string Subnet; //Subnet with CIDR notation will be at most 18 chars long
    int Distance; //Distance
    string FIPNext;
    string FMACNext;
    string RIPNext;
    int PortNext;
};

struct RT
{
    vector<RoutingInfo> *RoutingTable ;
    vector<RoutingInfo> *Neighbors;
} RoutingTable;

// ARP Table
// this is the ARP table used to store all the IP information
// about connected host
struct ARP
{
    vector<ARPValues> *ARPTable ;
    int PacketCount;
} ARPTable;

// IP Packet Header
// This is the IP packet header
// this struct holds the values used to make the header object
// for the initial IP Packet
typedef struct ip_packet_header
{
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

// LLC PDU Header
// This header stores the information for the second step thread
// this is information will eventually be added to an ip packet
typedef struct llc_pdu_header
{
    unsigned char DSAP;
    unsigned char SSAP;
    unsigned char LLCcontrol[2];
    ip_packet_header iph;
}LLC_PDU_HEADER_T;

// MAC Frame Header
// This mac frame header will store the MAC information used
// for the MAC frames that will eventually be sent
typedef struct mac_frame_header
{
    char PRE[7];
    char SFD;
    char DA[12];
    char SA[12];
    char IP[15];
    short length;
    llc_pdu_header llcpdu;
}MAC_FRAME_HEADER_T;

DWORD _stdcall DVRP(void *data)
{
    //Setup
    socklen_t addr_len;
    int packet_size;
    int max_packet_size;
    char IPAddress[1025];
    struct in_addr MyAddr;

    int i = 0;
    SOCKET clientSocket = *(SOCKET*)data;
    struct sockaddr_in RecvFrom;
    char buf[BUFLENDV+1];
    int numbytes;
    addr_len = sizeof(RecvFrom);

    // set socket to non-blocking
    u_long iMode=1; // enable non-blocking mode
    ioctlsocket(clientSocket,FIONBIO,&iMode);
    int error;
    DWORD start_time = GetTickCount();
    DWORD curr_time;

    //Send Initial DVRP String to Neighbors
    //Format of string : DVRP[my-ip-addr:myport my-sub-net/24 | conn-1-rip:port dist | ... ]
    //Building string
    char d[4];
    itoa(RoutingTable.RoutingTable->at(0).PortNext, d, 10);
    string DVRPstring ="DVRP[" + RoutingTable.RoutingTable->at(0).RIPNext + ":" + d + " " + RoutingTable.RoutingTable->at(0).Subnet;
    for(int i = 1; i < RoutingTable.RoutingTable->size(); i++)
    {
        char dist[4];
        itoa(RoutingTable.RoutingTable->at(i).Distance, dist, 10);
        DVRPstring += " | " + RoutingTable.RoutingTable->at(i).Subnet + " " + dist;
    }
    DVRPstring += "]";
    cout << DVRPstring << endl;

    //Send to neighbor routers
    struct sockaddr_storage n_addr;
    struct sockaddr_in neighbor;
    socklen_t n_len;

    for(int i = 0; i < RoutingTable.Neighbors->size(); i++)
    {
        neighbor.sin_family = AF_INET;
        neighbor.sin_addr.s_addr = inet_addr(RoutingTable.Neighbors->at(i).RIPNext.c_str());
        neighbor.sin_port = htons(RoutingTable.Neighbors->at(i).PortNext+1);
        n_len = sizeof neighbor;

        if (sendto(clientSocket, DVRPstring.c_str(), DVRPstring.length(), 0, (sockaddr*) &neighbor, n_len)==-1)
        {
            cout << "Error Sending" << endl;
        }
    }
    bool UpdateFlag = false;

    //Wait for Packets
    while(1)
    {
        if ( (numbytes = recvfrom(clientSocket, buf, BUFLENDV, 0, (sockaddr*) &RecvFrom, &addr_len))==-1)
        {
            error =  WSAGetLastError(); // if error == WSAEWOULDBLOCK, it means no data pending for this socket.
            if ( error== WSAEWOULDBLOCK || error == 10054)
            {
                curr_time = GetTickCount();
                if( curr_time - start_time > 5000) // timeout
                {
                    Sleep(10000);
                    start_time = GetTickCount();
                }
                continue;
            }
            else
            {
                cerr <<  "Could not receive datagram." << WSAGetLastError() << endl;
                closesocket(clientSocket);
                WSACleanup();
                exit(0);
            }
        }

        buf[numbytes] = '\0'; // append NULL to the end of the string
        //cout << buf << endl; //This prints out the DVRP String, I'm leaving this out because it will print all received DVRP strings and looks too messy in the output window.

        //Parse the DVRP String Here
        //Find port it comes from, find entry in Neighbors, update subnet??
        string newDVRP = string(buf);
        string tempstr;
        string tempNew;
        string subtemp1;
        string subtemp2;
        string disttemp;
        string fiptemp;
        string fmactemp;
        string riptemp;
        string portemp;
        for(int i = 5; i < newDVRP.length(); i++)
        {
            if(newDVRP[i] == '|')
            {
                break;
            }
            tempstr += newDVRP[i];
        }

        //parse router info
        size_t found;
        found = tempstr.find(":");
        riptemp = tempstr.substr(0, int(found));
        portemp = tempstr.substr(int(found)+1, 4);
        found = tempstr.find(" ");
        subtemp1 = tempstr.substr(int(found+1), tempstr.length());
        subtemp2 = subtemp1.substr(0, subtemp1.length()-1);

        //update neighbor
        for(int i = 0; i < RoutingTable.Neighbors->size(); i++)
        {
            if(RoutingTable.Neighbors->at(i).PortNext == atoi(portemp.c_str()) && RoutingTable.Neighbors->at(i).Subnet == "0.0.0.0/32")
            {
                RoutingTable.Neighbors->at(i).Subnet = subtemp2;
                //push to Routing Table as well
                RoutingTable.RoutingTable->push_back(RoutingTable.Neighbors->at(i));
                UpdateFlag = true;
            }
        }

        tempstr = newDVRP.substr(tempstr.length()+7, newDVRP.length());

        while(found != string::npos)
        {
            size_t newfound = tempstr.find(" ");
            subtemp1 = tempstr.substr(0, int(newfound));
            disttemp = tempstr.substr(int(newfound)+1, 1);
            int dist = atoi(disttemp.c_str())+1;
            RoutingInfo nfo = RoutingInfo();
            nfo.Distance = dist;
            nfo.FIPNext = subtemp1.substr(0, subtemp1.length()-3);
            nfo.PortNext = atoi(portemp.c_str());
            nfo.RIPNext = riptemp;
            nfo.Subnet = subtemp1;
            bool isThere = false;
            for(int i = 0; i < RoutingTable.RoutingTable->size(); i++)
            {
                if(RoutingTable.RoutingTable->at(i).Subnet == subtemp1)
                {
                    if(RoutingTable.RoutingTable->at(i).Distance > nfo.Distance)
                    {
                        //Update row ONLY!
                        RoutingTable.RoutingTable->at(i).FIPNext = nfo.FIPNext;
                        RoutingTable.RoutingTable->at(i).Distance = nfo.Distance;
                        RoutingTable.RoutingTable->at(i).PortNext = nfo.PortNext;
                        RoutingTable.RoutingTable->at(i).RIPNext = nfo.RIPNext;
                        RoutingTable.RoutingTable->at(i).Subnet = nfo.Subnet;
                        isThere = true;
                        UpdateFlag = true;
                        break;
                    }
                    isThere = true;
                }
            }
            if(!isThere)
            {
            RoutingTable.RoutingTable->push_back(nfo);
            UpdateFlag = true;
            }
            found = tempstr.find("|");
            if(found != string::npos)
            tempstr = tempstr.substr(int(found)+2, tempstr.length());
        }

        if(UpdateFlag)
        {
            cout << "UDATED ROUTING TABLE" << endl << "=======================================================" << endl;
            cout << "DEST        LINK                 COST" << endl;


            for (int i = 0; i < RoutingTable.RoutingTable->size(); i++)
            {
                cout << RoutingTable.RoutingTable->at(i).Subnet << "  " << RoutingTable.RoutingTable->at(i).RIPNext << ":" << RoutingTable.RoutingTable->at(i).PortNext << "  " << RoutingTable.RoutingTable->at(i).Distance << endl;
            }
            cout << "=======================================================" << endl;
            cout << "NEIGHBORS ROUTERS:"<<endl;
            for (int i = 0; i < RoutingTable.Neighbors->size(); i++)
            {
                cout << RoutingTable.Neighbors->at(i).RIPNext << ":" << RoutingTable.Neighbors->at(i).PortNext << endl;

            }
            cout << "=======================================================" << endl;

            //Resend the new DVRP String
            //Format of string : DVRP[my-ip-addr:myport my-sub-net/24 | conn-1-rip:port dist | ... ]
            //Building string
            char d[4];
            itoa(RoutingTable.RoutingTable->at(0).PortNext, d, 10);
            DVRPstring ="DVRP[" + RoutingTable.RoutingTable->at(0).RIPNext + ":" + d + " " + RoutingTable.RoutingTable->at(0).Subnet ;
            for(int i = 1; i < RoutingTable.RoutingTable->size(); i++)
            {
                char dist[4];
                itoa(RoutingTable.RoutingTable->at(i).Distance, dist, 10);
                DVRPstring += " | " + RoutingTable.RoutingTable->at(i).Subnet + " " + dist;
            }
            DVRPstring += "]";
            cout << DVRPstring << endl;

            //Send DVRP String Again!
            for(int i = 0; i < RoutingTable.Neighbors->size(); i++)
            {
                neighbor.sin_family = AF_INET;
                neighbor.sin_addr.s_addr = inet_addr(RoutingTable.Neighbors->at(i).RIPNext.c_str());
                neighbor.sin_port = htons(RoutingTable.Neighbors->at(i).PortNext+1);
                n_len = sizeof neighbor;

                if (sendto(clientSocket, DVRPstring.c_str(), DVRPstring.length(), 0, (sockaddr*) &neighbor, n_len)==-1)
                {
                    cout << "Error Sending" << endl;
                }
            }

            UpdateFlag = false;
        }
        Sleep(100);
    }
    return 0;
}


int main(int argc, char* argv[])
{
    //WINSOCK setup
    WSADATA w;
    struct addrinfo hints, hintsdvrp, *servinfo, *servinfodvrp, *p, *pdvrp;
    struct sockaddr_storage their_addr, fwd_addr;
    struct sockaddr_in sin;
    struct sockaddr_in fwd;
    socklen_t addr_len;
    socklen_t fwd_len;

    //LOCAL information
    char* LocalMac;
    char* LocalPort;
    char* LocalFIP;
    char* RoutingTableFile;

    hostent* hp;
    struct in_addr my_addr;
    int my_port;
    int DVRP_port;
    char my_hostname[NI_MAXHOST];

    //Socket to use
    SOCKET socketfd;
    SOCKET socketdvrp;

    int numbytes;
    int i;
    char buf[BUFLEN+1];
    char host[NI_MAXHOST], port[NI_MAXSERV]; // to hold the address and port of the remote host
    int rv; // return value
    int rv2;

    header_t header; // to store the header
    char message[MAX_MSG_SIZE+1]; // for the message

    //Parse the Params
    if(argc !=5)
    {
        cout <<"Execute like: Switch [Fake Mac addr] [Real Port number]"<<endl;
    }
    LocalMac = argv[3];
    LocalPort = argv[1];
    LocalFIP = argv[2];
    RoutingTableFile = argv[4];

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0)
    {
        cerr << "Could not open Windows connection." << endl;
        exit(1);
    }

    // Open a (UDP) datagram socket
    socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    socketdvrp = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketfd == INVALID_SOCKET)
    {
        cerr <<  "Could not create socket." << endl;
        WSACleanup();
        exit(1);
    }
    if (socketdvrp == INVALID_SOCKET)
    {
        cerr <<  "Could not create socket DVRP." << endl;
        WSACleanup();
        exit(1);
    }

    // Clear out hints struct
    ZeroMemory( &hints, sizeof(hints) );
    ZeroMemory( &hintsdvrp, sizeof(hints));

    // Set family and port
    hints.ai_family = AF_INET;      // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    hintsdvrp.ai_family = AF_INET;      // set to AF_INET to force IPv4
    hintsdvrp.ai_socktype = SOCK_DGRAM;
    hintsdvrp.ai_flags = AI_PASSIVE; // use my IP

    int dvrpport = atoi(LocalPort) + 1;
    char* dvrpPort = new char[5];
    itoa(dvrpport, dvrpPort, 10);

    // get address info
    if ((rv = getaddrinfo(NULL, LocalPort, &hints, &servinfo)) != 0)
    {
        cerr << "getaddrinfo: " << gai_strerror(rv) << endl;
        exit(1);
    }
    if ((rv2 = getaddrinfo(NULL, dvrpPort, &hintsdvrp, &servinfodvrp)) != 0)
    {
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

    for(pdvrp = servinfodvrp; pdvrp != NULL; pdvrp = pdvrp->ai_next)
    {
        if ((socketdvrp = socket(pdvrp->ai_family, pdvrp->ai_socktype, pdvrp->ai_protocol)) == -1)
        {
            cerr << "server: socket" << endl;
            continue;
        }

        if (bind(socketdvrp, pdvrp->ai_addr, pdvrp->ai_addrlen) == -1)
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
    if (pdvrp == NULL)
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
    if( getsockname( socketdvrp, (sockaddr *)&sin, &addr_len) != 0 )
    {
        cerr << "server: getsockname" << endl;
        WSACleanup();
        exit(1);
    }

    // The IP address is 0.0.0.0 (INADDR_ANY)
    my_port = ntohs(sin.sin_port);
    DVRP_port = ntohs(sin.sin_port);
    DVRP_port += 1;

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

    /* Open Routing File and Parse Routing Table Info */
    //Initialize Routing Table
    RoutingTable.RoutingTable = new vector<RoutingInfo> ();
    RoutingTable.Neighbors = new vector<RoutingInfo> ();

    //Temp String Line
    string RtFileLine;
    //Open File Stream
    ifstream myfile (RoutingTableFile);
    if(myfile.is_open())
    {
        int number = 0;
        //Print Out Routing Table Header

        while(myfile.good())
        {
            getline(myfile,RtFileLine);

            //Create a new Table Object
            RoutingInfo nfo = RoutingInfo();

            //Parse Elements
            if(number == 0)
            {
                //If its the subnet
                nfo.Subnet = RtFileLine.substr(0, 10);
                nfo.Distance = 0;
                nfo.FIPNext = RtFileLine.substr(0, 7);
                nfo.FMACNext = LocalMac;
                nfo.PortNext = atoi(LocalPort);
                nfo.RIPNext = inet_ntoa(my_addr);

                RoutingTable.RoutingTable->push_back(nfo);
            }
            else
            {
                nfo.Subnet = RtFileLine.substr(0, 10);
                nfo.Distance = atoi(RtFileLine.substr(11, 1).c_str());
                if(nfo.Distance == 0) nfo.Distance = 1; //We do this to show that the next hop has distance 1 to the switch that this is connected to
                nfo.FIPNext = RtFileLine.substr(13, 7);
                nfo.FMACNext = RtFileLine.substr(21 , 17);
                nfo.RIPNext = inet_ntoa(my_addr);//RtFileLine.substr(48 , 11);
                nfo.PortNext = atoi(RtFileLine.substr(52, 5).c_str());

                cout << nfo.PortNext << endl;
                if(nfo.Subnet == "0.0.0.0/32")
                {
                    RoutingTable.Neighbors->push_back(nfo);
                }
                else
                {
                    RoutingTable.RoutingTable->push_back(nfo);
                }
            }
            number++;
        }
        myfile.close();

        cout << "INITIAL ROUTING TABLE" << endl << "=======================================================" << endl;
        cout << "DEST        LINK                 COST" << endl;

        for (int i = 0; i < RoutingTable.RoutingTable->size(); i++)
        {
            cout << RoutingTable.RoutingTable->at(i).Subnet << "  " << RoutingTable.RoutingTable->at(i).RIPNext << ":" << RoutingTable.RoutingTable->at(i).PortNext << "  " << RoutingTable.RoutingTable->at(i).Distance << endl;
        }
        cout << "=======================================================" << endl;
        cout << "NEIGHBORS ROUTERS:"<<endl;
        for (int i = 0; i < RoutingTable.Neighbors->size(); i++)
        {
                cout << RoutingTable.Neighbors->at(i).RIPNext << ":" << RoutingTable.Neighbors->at(i).PortNext << endl;
        }
        cout << "=======================================================" << endl;
    }
    else
    {
        cout << "Unable to Open Routing Table File" << endl;
        return -1;
    }

    int PacketCount = 0; // We will keep track of the number of Datagram packets are receieved.

    // receive packets and send ACKs
    addr_len = sizeof their_addr;
    CreateThread(NULL, 0, DVRP, (void*)&socketdvrp, 0, NULL);

    while(1)
    {
        // receive the packet
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

        //If we are here, we are seeing a regular Data Packet as A MAC FRAME
        //Extract IP Addr and MAC Addr

        //Increment the counter
        PacketCount ++;
        //Info to extract from message

        //Parse Mac Frame
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

        //Convert IP Addrs
        char DIP[16];
        char SIP[16];
        inet_ntop(AF_INET, &mfh.llcpdu.iph.DIP, DIP ,15);
        inet_ntop(AF_INET, &mfh.llcpdu.iph.SIP, SIP ,15);
        DIP[15] = '\0';
        SIP[15] = '\0';

        //Older IP Addr Converstion, still here for older code reused from switch
        char IPAddrRecv[16];
        char MACAddrRecv[13];
        strncpy(IPAddrRecv, &buf[34], 15);
        IPAddrRecv[15] = '\0';
        strncpy(MACAddrRecv, &buf[8], 12);
        MACAddrRecv[12]='\0';
        char MACAddrChange[13];

        //Check to see if the MAC Frame is for the switch it comes from.
        //If so discard it
        //IP Addr to use
        char DIPTest[13];
        char SIPTest[13];
        strncpy(DIPTest, DIP, 12);
        DIPTest[12] = '\0';
        strncpy(SIPTest, SIP, 12);
        SIPTest[12] = '\0';
        string Destination = string(DIP);

        //Find the entry on Routing Table, If not there discard the frame
        for(int i = 1; i < RoutingTable.RoutingTable->size(); i++)
        {
            if(Destination.substr(0, Destination.length() - 4) == RoutingTable.RoutingTable->at(i).FIPNext.substr(0, RoutingTable.RoutingTable->at(i).FIPNext.length()-2))
            {
                //Forward MAC Frame using the same buf?
                fwd.sin_family = AF_INET;
                fwd.sin_addr.s_addr = inet_addr(RoutingTable.RoutingTable->at(i).RIPNext.c_str());
                fwd.sin_port = htons(RoutingTable.RoutingTable->at(i).PortNext);
                fwd_len = sizeof fwd;
                if (sendto(socketfd, buf, BUFLEN, 0, (sockaddr*) &fwd, fwd_len)==-1)
                {
                    //cout << "Unable To Forward Sending Back"<< endl;
                    cout <<"[RT] Frame " << PacketCount << " received (" << numbytes << " bytes)." << endl;
                    cout <<"[RT] DST: " << DIP << endl;
                    cout <<"[RT] SRC: " <<  SIP << endl;
                    cout << "[RT] Fragment: " << mfh.llcpdu.iph.fragment_seq + 1 << " out of " << mfh.llcpdu.iph.total_fragments << endl;
                    cout << "Error: Destination is not reachable." << endl;
                }
                else
                {
                    //It sent successfully Update screen

                    char DIP1[16];
                    char SIP1[16];
                    inet_ntop(AF_INET, &mfh.llcpdu.iph.DIP, DIP1 ,15);
                    inet_ntop(AF_INET, &mfh.llcpdu.iph.SIP, SIP1 ,15);
                    DIP1[15] = '\0';
                    SIP1[15] = '\0';

                    cout <<"[RT] Frame " << PacketCount << " received (" << numbytes << " bytes)." << endl;
                    cout <<"[RT] DST: " << DIP << endl;
                    cout <<"[RT] SRC: " <<  SIP << endl;
                    cout << "[RT] Next Hop: " << RoutingTable.RoutingTable->at(i).FIPNext << endl;
                    cout << "[RT] Fragment: " << mfh.llcpdu.iph.fragment_seq + 1 << " out of " << mfh.llcpdu.iph.total_fragments << endl;
                }
            }
        }
    }

    //Program Cleanup
    closesocket(socketfd);
    WSACleanup();
    return 0;
}