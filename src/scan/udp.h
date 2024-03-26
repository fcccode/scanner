#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//ժ�ԣ�Windows-classic-samples\Samples\Win7Samples\netds\winsock\iphdrinc\iphdr.h
typedef struct udp_hdr
{// Define the UDP header 
    unsigned short src_portno;       // Source port no.
    unsigned short dst_portno;       // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum
} UDP_HDR, * PUDP_HDR;


//////////////////////////////////////////////////////////////////////////////////////////////////


void test_udp4(const char * source);
