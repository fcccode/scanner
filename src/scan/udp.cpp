#include "udp.h"


void test_udp4(const char * source)
/*
功能：构造一个走IPv4的UDP。

本程序是构造如下的内容：
0000   dc f8 b9 bf 2b 28 2c 6d c1 0f d4 62 08 00 45 00   ....+(,m...b..E.
0010   00 3b 1f 95 00 00 40 11 00 00 c0 a8 05 03 08 08   .;....@.........
0020   08 08 cc 4d 00 35 00 27 d5 f3 2a 9a 01 00 00 01   ...M.5.'..*.....
0030   00 00 00 00 00 00 03 72 65 73 02 77 78 02 71 71   .......res.wx.qq
0040   03 63 6f 6d 00 00 01 00 01                        .com.....

说明：实验成功，pcap_sendpacket成功，wireshark也抓到了。
*/
{
    pcap_t * fp;
    int snaplen = 65536;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((fp = pcap_open(source,				// name of the device
                        snaplen,// portion of the packet to capture
                        PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                        1,				    // read timeout
                        NULL,				// authentication on the remote machine
                        errbuf				// error buffer
    )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", source);
        return;
    }

    UINT8 SrcMac[6] = {0x2c, 0x6d, 0xc1, 0x0f, 0xd4, 0x62};
    //GetMacAddress(source, SrcMac);

    IN_ADDR SourceAddress;
    SourceAddress.S_un.S_addr = inet_addr("192.168.5.3");
    //GetOneAddress(source, &SourceAddress, NULL, NULL);

    IN_ADDR DestinationAddress;
    DestinationAddress.S_un.S_addr = inet_addr("8.8.8.8");

    UINT8 DesMac[6] = {0xdc, 0xf8, 0xb9, 0xbf, 0x2b, 0x28};
    //GetGatewayMacByIPv4(inet_ntoa(SourceAddress), DesMac);

    BYTE buf[] = {0x2a,0x9a,0x01,0x00,0x00,0x01,\
        0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x72,0x65,0x73,0x02,0x77,0x78,0x02,0x71,0x71,\
        0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01};
    u_short len = sizeof(buf);

    //////////////////////////////////////////////////////////////////////////////////////////////

    int Length = sizeof(ETHERNET_HEADER) + sizeof(IPV4_HEADER) + sizeof(UDP_HDR) + len;
    PETHERNET_HEADER eth = (PETHERNET_HEADER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (!eth) {
        fprintf(stderr, "FILE:%hs, LINE:%d，申请内存失败:%d。\n", __FILE__, __LINE__, Length);
        return;
    }

    memcpy((void *)&eth->Source, (void *)&SrcMac, sizeof(DL_EUI48));
    memcpy((void *)&eth->Destination, (void *)&DesMac, sizeof(DL_EUI48));
    eth->Type = ntohs(ETHERNET_TYPE_IPV4);

    PIPV4_HEADER tmp = (PIPV4_HEADER)((PBYTE)eth + ETH_LENGTH_OF_HEADER);
    tmp->VersionAndHeaderLength = 0x45;
    tmp->TypeOfServiceAndEcnField = 0;
    tmp->TotalLength = htons((UINT16)Length - sizeof(ETHERNET_HEADER));
    tmp->Identification = htons(0x1f95);// ipv4->Identification + 1;
    tmp->FlagsAndOffset = 0;
    tmp->TimeToLive = 64;
    tmp->Protocol = IPPROTO_UDP;
    tmp->SourceAddress.S_un.S_addr = SourceAddress.S_un.S_addr;
    tmp->DestinationAddress.S_un.S_addr = DestinationAddress.S_un.S_addr;
    tmp->HeaderChecksum = 0;
    tmp->HeaderChecksum = checksum((USHORT *)tmp, sizeof(IPV4_HEADER));//要不要转换字节序？

    PUDP_HDR udp = (PUDP_HDR)((PBYTE)tmp + sizeof(IPV4_HEADER));

    PVOID udp_data = (PUDP_HDR)((PBYTE)udp + sizeof(UDP_HDR));
    memcpy(udp_data, buf, len);

    udp->dst_portno = htons(53);
    udp->src_portno = htons(0xcc4d);
    udp->udp_length = htons(len + sizeof(UDP_HDR));
    udp->udp_checksum = 0;
    udp->udp_checksum = calc_udp4_sum((USHORT *)eth, Length);//要不要转换字节序？

    int ret = pcap_sendpacket(fp, (const u_char *)eth, Length);
    if (ret != 0) {
        fprintf(stderr, "\nFILE:%hs, LINE:%d, Error sending the packet: %s\n",
                __FILE__, __LINE__, pcap_geterr(fp));
    } else {
        fprintf(stderr, "发送成功，发送长度：%d。\n", Length);
    }

    HeapFree(GetProcessHeap(), 0, eth);

    //////////////////////////////////////////////////////////////////////////////////////////////

    //UINT res;
    //struct pcap_pkthdr * header;
    //const BYTE * pkt_data;
    //while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
    //    if (res == 0)
    //        continue;

    //    if (pkt_data) {
    //        //ParsePacket(header, pkt_data);
    //    }
    //}
}
