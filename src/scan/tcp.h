#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////





//////////////////////////////////////////////////////////////////////////////////////////////////


void SendSyn4(pcap_t * fp,
			  PUINT8 SrcMac,
			  PBYTE DesMac,
			  PIN_ADDR SourceAddress,
			  PIN_ADDR DestinationAddress,
			  WORD RemotePort
);


void SendSyn6(pcap_t * fp,
              PUINT8 SrcMac,
              PBYTE DesMac,
              PIN6_ADDR SourceAddress,
              PIN6_ADDR DestinationAddress,
              WORD RemotePort
);


void ParsePacket(struct pcap_pkthdr * header, const BYTE * pkt_data);


void Syn4ScanTest(const char * source, const char * RemoteIPv4, WORD RemotePort);
void Syn6ScanTest(const char * source, const char * RemoteIPv6, WORD RemotePort);
