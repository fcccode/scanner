/*
������Ҫ����ʵ�ֶ��̵߳�����

ע�⣺ʵ�ְ취�õ��˺���ģ�塣
*/

#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


struct _ScanContext;//�ṹǰ��������


typedef void (WINAPI * ReplyCallBack)(struct pcap_pkthdr * header,
                                      const BYTE * pkt_data,
                                      _ScanContext * ScanContext);//�ص�������ԭ�͡�


/*
���廥������ַ������IPv4/6���������˿ڣ������˿ڵ���Ϣ�ɲο�SOCKADDR_INET��

�޸��ԣ�\Windows Kits\10\Include\10.0.19041.0\um\Mprapi.h��VPN_TS_IP_ADDRESS��
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
����ɨ������ݽṹ��֧��IPv4/6���������룬�˿ڷֶΣ�ɨ�����͵ȵȡ�
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

    //һ������IPv4ר�á�
    DWORD start;
    DWORD len;
    BYTE mask;//ȡֵ[0,32].
} SCAN_CONTEXT, * PSCAN_CONTEXT;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LONG volatile g_stop_scan;

DWORD WINAPI ScanAllIPv4Thread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv4SubnetScanThread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv4PortScanThread(_In_ LPVOID lpParameter);
DWORD WINAPI IPv6PortScanThread(_In_ LPVOID lpParameter);
