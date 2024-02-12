/*
此文主要用于实现多线程的需求。

注意：实现办法用到了函数模板。
*/

#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


struct _ScanContext;//结构前置声明。


typedef void (WINAPI * ReplyCallBack)(struct pcap_pkthdr * header,
                                      const BYTE * pkt_data,
                                      _ScanContext * ScanContext);//回调函数的原型。


/*
定义互联网地址，包含IPv4/6，不包含端口，包含端口的信息可参考SOCKADDR_INET。

修改自：\Windows Kits\10\Include\10.0.19041.0\um\Mprapi.h的VPN_TS_IP_ADDRESS。
*/
typedef struct _IP_ADDRESS {
    ADDRESS_FAMILY Family;
    union
    {
        IN_ADDR IPv4;           // The v4 address, if the family == AF_INET .
        IN6_ADDR IPv6;          // The v6 address, if the family == AF_INET6.
    };
}IP_ADDRESS, * PIP_ADDRESS;


/*
用于扫描的数据结构，支持IPv4/6，子网掩码，端口分段，扫描类型等等。
*/
typedef struct _ScanContext {
    pcap_t * fp;
    string * FileName;

    UINT8 SrcMac[6];
    UINT8 DesMac[6];

    IP_ADDRESS SourceAddress;
    IP_ADDRESS DestinationAddress;

    WORD RemotePort;

    WORD StartPort;
    WORD EndPort;

    ReplyCallBack CallBack;

    //一下三个IPv4专用。
    DWORD start;
    DWORD len;
    BYTE mask;//取值[0,32].
} SCAN_CONTEXT, * PSCAN_CONTEXT;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LONG volatile g_stop_scan;

DWORD WINAPI ScanAllIPv4Thread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv4SubnetScanThread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv4PortScanThread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv6PortScanThread(_In_ LPVOID lpParameter);
