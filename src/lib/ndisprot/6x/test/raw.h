#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <netiodef.h>
#include <Windows.h>
#include <crtdbg.h>


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
可复制或参考
\Windows-classic-samples\Samples\Win7Samples\netds\winsock\rcvall\iphdr.h
\Windows-classic-samples\Samples\Win7Samples\netds\winsock\iphdrinc\iphdr.h
*/


#define DEFAULT_TTL           8             // default TTL value


#include <pshpack1.h>


//
// IPv4 Header (without any IP options)
//
typedef struct ip_hdr
{
    unsigned char  ip_verlen;        // 4-bit IPv4 version
                                     // 4-bit header length (in 32-bit words)
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier 
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Source address
} IPV4_HDR, * PIPV4_HDR, FAR * LPIPV4_HDR;


#pragma warning(push)
#pragma warning(disable : 4200) //使用了非标准扩展: 结构/联合中的零大小数组
typedef struct raw_tcp
{
    ETHERNET_HEADER eth_hdr;
    IPV4_HDR ip_hdr;
    TCP_HDR tcp_hdr;
    BYTE data[0];
} RAW_TCP, * PRAW_TCP;
#pragma warning(pop)  


#include <poppack.h>


//////////////////////////////////////////////////////////////////////////////////////////////////


extern const char * SRC_IP;
extern u_short sport;

extern const char * DEST_IP;
extern u_short dport;


void InitRawTcp(PRAW_TCP buffer);
void raw(HANDLE  Handle);
