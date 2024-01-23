#include "raw.h"


const char * SRC_IP = "192.168.174.133";//
u_short sport = 8888;

const char * DEST_IP = "192.168.18.132";//
u_short dport = 8080;


#pragma comment(lib,"ws2_32.lib")


//////////////////////////////////////////////////////////////////////////////////////////////////


USHORT checksum(USHORT * buffer, int size)
// Description:摘自\netds\winsock\iphdrinc\rawudp.c
//    This function calculates the 16-bit one's complement sum for the supplied buffer.
{
    unsigned long cksum = 0;

    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }

    // If the buffer was not a multiple of 16-bits, add the last byte
    if (size) {
        cksum += *(UCHAR *)buffer;
    }

    // Add the low order 16-bits to the high order 16-bits
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    // Take the 1's complement
    return (USHORT)(~cksum);
}


void InitEthernetHeader(PRAW_TCP buffer)
{
    buffer->eth_hdr.Destination.Byte[0] = 0x00;
    buffer->eth_hdr.Destination.Byte[1] = 0x50;
    buffer->eth_hdr.Destination.Byte[2] = 0x56;
    buffer->eth_hdr.Destination.Byte[3] = 0xc0;
    buffer->eth_hdr.Destination.Byte[4] = 0x00;
    buffer->eth_hdr.Destination.Byte[5] = 0x08;

    buffer->eth_hdr.Source.Byte[0] = 0x00;
    buffer->eth_hdr.Source.Byte[1] = 0x0c;
    buffer->eth_hdr.Source.Byte[2] = 0x29;
    buffer->eth_hdr.Source.Byte[3] = 0x3f;
    buffer->eth_hdr.Source.Byte[4] = 0x0e;
    buffer->eth_hdr.Source.Byte[5] = 0x2e;    

    buffer->eth_hdr.Type = htons(ETHERNET_TYPE_IPV4);//ETHERNET_TYPE_IPV6
}


void InitIpv4HeaderForTcp(PRAW_TCP buffer)
// Description:
//    Initialize the IPv4 header with the version, header length,
//    total length, ttl, protocol value, and source and destination addresses.
{
    if (NULL == buffer) {
        return;
    }

    IN_ADDR src;
    IN_ADDR dest;

    IPV4_HDR * v4hdr = &buffer->ip_hdr;

    if (NULL == v4hdr) {
        return;
    }

    src.S_un.S_addr = inet_addr(SRC_IP);
    dest.S_un.S_addr = inet_addr(DEST_IP);

    v4hdr->ip_verlen = (4 << 4) | (sizeof(IPV4_HDR) / sizeof(unsigned long));
    v4hdr->ip_tos = 0;
    v4hdr->ip_totallength = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR)); //还有内容，可以再加别的。
    v4hdr->ip_id = 0;
    v4hdr->ip_offset = 0;
    v4hdr->ip_ttl = DEFAULT_TTL;
    v4hdr->ip_protocol = IPPROTO_TCP;
    v4hdr->ip_checksum = 0;
    v4hdr->ip_srcaddr = src.S_un.S_addr;
    v4hdr->ip_destaddr = dest.S_un.S_addr;

    v4hdr->ip_checksum = checksum((unsigned short *)v4hdr, sizeof(IPV4_HDR));
}


void InitTcpHeader(PRAW_TCP buffer)
{
    if (NULL == buffer) {
        return;
    }

    PTCP_HDR tcp_hdr = &buffer->tcp_hdr;

    if (NULL == tcp_hdr) {
        return;
    }

    tcp_hdr->th_sport = htons(sport);
    tcp_hdr->th_dport = htons(dport);
    tcp_hdr->th_seq = htonl(0x99999999);
    tcp_hdr->th_ack = 0;

    UINT8 x = (sizeof(TCP_HDR) / 4);//<< 4 | 0
    //tcp_hdr->th_len = (sizeof(TCP_HDR) / 4 << 4 | 0);
    _ASSERTE(x <= 0xf);//大于这个数会发生溢出，有想不到的结果。    
    tcp_hdr->th_len = x;

    tcp_hdr->th_flags = 2;
    tcp_hdr->th_win = htons(620);
    tcp_hdr->th_sum = 0;
    tcp_hdr->th_urp = 0;

    tcp_hdr->th_sum = checksum((USHORT *)buffer, sizeof(IPV4_HDR) + sizeof(TCP_HDR));
}


void InitRawTcp(PRAW_TCP buffer)
{
    if (NULL == buffer) {
        return;
    }

    InitEthernetHeader(buffer);
    InitIpv4HeaderForTcp(buffer);
    InitTcpHeader(buffer);
}


//VOID DoWriteProc(HANDLE  Handle)
void raw(HANDLE  Handle)
{
    RAW_TCP buffer = {0};
    InitRawTcp(&buffer);

    DWORD BytesWritten = 0;
    BOOLEAN bSuccess = (BOOLEAN)WriteFile(Handle, &buffer, sizeof(RAW_TCP), &BytesWritten, NULL);
    if (!bSuccess) {        
        int x = GetLastError();        
        DebugBreak();
        x = 0;
    }
}
