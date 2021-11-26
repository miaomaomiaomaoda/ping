/**
 * @file ping.cpp
 * @author zero.nj
 * @brief 
 * @version 0.1
 * @date 2021-11-26
 * 
 * @copyright Copyright (c) 2021
 * g++ version 8.1.0
 * System Windows
 */

#pragma comment(lib, "ws2_32.lib")
#include <Winsock2.h>
#include <iostream>
#include <string.h>
#include <sys/time.h>
using namespace std;

//global varied
SOCKET raw_socket = INVALID_SOCKET;
SOCKADDR_IN DestAddr;
SOCKADDR_IN SourceAddr;
char InputBuffer[200];

//const defined
#define MAGIC_ERROR -1
#define PACKAGE_NUM 4
#define ICMP_ECHO 8      //type->回显请求
#define ICMP_ECHOREPLY 0 //type->回显应答
#define ICMP_CODE 0      //type->回显请求
#define IP_HEADER 20
#define ICMP_HEADER 8
#define PACKAGE_SIZE 12
#define PACKAGE_MAX_SIZE 1472 //(1500 - 20 - 8)

//struct define
struct icmp_echo
{
    // header(8B)
    uint8_t type;      //8位ICMP报文类型
    uint8_t code;      //8位代码
    uint16_t checksum; //16位校验和
    uint16_t id;       //惟一的标识符
    uint16_t seq;      //16位报文序列号

    // data(4)
    double timestamp; //32位时间戳
};

//initial the setting
void init()
{
    //load the winsockDLL
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "WSAStartup() failed: " << GetLastError() << endl;
        return;
    }

    //create raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    //raw_socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (raw_socket == INVALID_SOCKET)
    {
        cout << "WSASocket() failed: " << WSAGetLastError() << endl;
        return;
    }

    //set socket timeout option
    int timeout = 10000;
    int ret, ret1;
    ret = setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    ret1 = setsockopt(raw_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    if (ret == MAGIC_ERROR || ret1 == MAGIC_ERROR)
    {
        cout << "setsockopt failed: " << WSAGetLastError() << endl;
        return;
    }
}

//get DestIp, return destIp
char *getDestIp()
{
    char *destIp = NULL;
    gets(InputBuffer);

    int i = 0, j = 0;
    while (InputBuffer[i++])
        if (InputBuffer[i] == ' ')
            break;

    destIp = &InputBuffer[++i];
    return destIp;
}

//initial DestAddress
void initDestAddr(char *destIP)
{
    //fill the DestAddr
    memset(&DestAddr, 0, sizeof(DestAddr));
    DestAddr.sin_family = AF_INET;
    DestAddr.sin_port = 0;

    //check if the destIP is IP address
    if ((DestAddr.sin_addr.s_addr = inet_addr(destIP)) == INADDR_NONE)
    {
        //hostent ,as host entry ,store the infomations of host
        struct hostent *host = NULL;

        //if not(ffffffff) ,to get it's IP
        if ((host = gethostbyname(destIP)) != NULL)
        {
            memcpy(&(DestAddr.sin_addr), host->h_addr, host->h_length);
            DestAddr.sin_family = host->h_addrtype;
            cout << "Destination:" << inet_ntoa(DestAddr.sin_addr) << endl;
        }
        else
        {
            cout << "gethostbyname() failed: " << WSAGetLastError() << endl;
            return;
        }
    }
}

//calculate the checksum
USHORT CheckSum(unsigned char *buffer, int bytes)
{
    uint32_t checksum = 0;
    unsigned char *end = buffer + bytes;

    // odd bytes add last byte and reset end
    if (bytes % 2 == 1)
    {
        end = buffer + bytes - 1;
        checksum += (*end) << 8;
    }

    // add words of two bytes, one by one
    while (buffer < end)
    {
        checksum += buffer[0] << 8;
        checksum += buffer[1];
        buffer += 2;
    }

    // add carry if any
    uint32_t carray = checksum >> 16;
    while (carray)
    {
        checksum = (checksum & 0xffff) + carray;
        carray = checksum >> 16;
    }

    // negate it
    checksum = ~checksum;
    return checksum & 0xffff;
}

//get the timestamp
double get_timestamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + ((double)tv.tv_usec) / 1000000;
}

//send package , return the result
int send_echo_request(int seq)
{
    //allocate memory for icmp data
    struct icmp_echo icmp;
    memset(&icmp, 0, PACKAGE_SIZE);

    //fill the header，回显请求
    icmp.type = ICMP_ECHO;
    icmp.code = ICMP_CODE;
    icmp.id = htons(GetCurrentProcessId());
    icmp.seq = htons(seq);

    //fill the timestamp
    icmp.timestamp = get_timestamp();

    //calculate and fill checksum
    icmp.checksum = htons(CheckSum((unsigned char *)&icmp, sizeof(icmp)));

    //send the package
    int bytes = sendto(raw_socket, (char *)&icmp, sizeof(icmp), 0, (struct sockaddr *)&DestAddr, sizeof(DestAddr));
    return bytes == -1 ? -1 : 0;
}

//receive the package, return the result
int recv_echo_reply()
{
    char buffer[PACKAGE_MAX_SIZE];

    //receiver packet
    int fromlen = sizeof(SourceAddr);
    int bytes = recvfrom(raw_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&SourceAddr, &fromlen);

    //if occur error,then return it;
    if (bytes == SOCKET_ERROR)
    {
        return bytes;
    }

    //decode the icmp package
    struct icmp_echo *icmp = (struct icmp_echo *)(buffer + IP_HEADER);

    //check icmp type
    if (icmp->type != ICMP_ECHOREPLY)
    {
        //if not 回显报文
        cout << "non-echo type of" << icmp->type << "is received" << endl;
        return 0;
    }

    //check icmp code
    if (icmp->code != ICMP_CODE)
    {
        return 0;
    }

    //check the id
    if (icmp->id != htons(GetCurrentProcessId()))
    {
        cout << "someone else's packet!" << endl;
        return 0;
    }

    //print the timestamp info
    cout << bytes << " bytes from " << inet_ntoa(SourceAddr.sin_addr) << " 时间t=" << (get_timestamp() - icmp->timestamp) * 1000 << "ms" << endl;
    return 0;
}

//print the statistics
void printStatistics(char *destIP, int send_miss, int recv_miss)
{
    cout << inet_ntoa(SourceAddr.sin_addr) << "'s ping Statistics:" << endl;
    cout << "Package: sent = " << send_miss << ", accepted = " << recv_miss << ", loss = " << send_miss - recv_miss << endl;
}

//ping
void ping(char *destIP)
{
    initDestAddr(destIP);

    //start to send and recive package
    int ret;
    int seq = 0;
    int send_miss = PACKAGE_NUM;
    int recv_miss = PACKAGE_NUM;
    for (int i = 0; i < PACKAGE_NUM; i++)
    {
        //send the icmp_echo
        ret = send_echo_request(seq);
        if (ret == SOCKET_ERROR)
        {
            //over the timelimit , then send_miss--
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                cout << "timed out" << endl;
                send_miss--;
                continue;
            }

            cout << "send ICMP_ECHO failed: " << WSAGetLastError() << endl;
            return;
        }

        seq++;

        //receive the package
        ret = recv_echo_reply();
        if (ret == SOCKET_ERROR)
        {
            //over the timelimit , then recv_miss--
            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                cout << "timed out" << endl;
                recv_miss--;
                continue;
            }

            cout << "RECV ICMP_ECHO failed: " << WSAGetLastError() << endl;
            return;
        }

        Sleep(100);
    }
    printStatistics(destIP, send_miss, recv_miss);
}

//free the resource
void freeRes()
{
    if (raw_socket != INVALID_SOCKET)
        closesocket(raw_socket);
    WSACleanup();
}

int main(int argc, char *argv[])
{
    while (1)
    {
        cout << ">";
        char *destIp;

        //initial the setting
        init();

        //get the destIP
        destIp = getDestIp();
        if ((*destIp) == '\0')
        {
            cout << "Not dest IP,please repeat input it" << endl;
            continue;
        }

        //start ping destIP
        ping(destIp);

        //free the resource
        freeRes();
    }
}