#include "pch.h"


#pragma warning(disable:4244)
#pragma warning(disable:26451)
#pragma warning(disable:6067)
#pragma warning(disable:28183)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL LoadNpcapDlls()
//摘自：npcap-sdk-1.07\Examples-remote\misc\misc.h
{
    _TCHAR npcap_dir[512];
    UINT len;

    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }

    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }

    return TRUE;
}


int RangedRand(int range_min, int range_max)
//https://docs.microsoft.com/zh-cn/cpp/c-runtime-library/reference/rand?view=msvc-170
{
    // Generate random numbers in the interval [range_min, range_max], inclusive.

        // Note: This method of generating random numbers in a range isn't suitable for
        // applications that require high quality random numbers.
        // rand() has a small output range [0,32767], making it unsuitable for
        // generating random numbers across a large range using the method below.
        // The approach below also may result in a non-uniform distribution.
        // More robust random number functionality is available in the C++ <random> header.
        // See https://docs.microsoft.com/cpp/standard-library/random
    return (int)(((double)rand() / RAND_MAX) * (range_max - range_min) + range_min);
}


void ErrorHandler(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code.

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  dw,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR)&lpMsgBuf,
                  0, NULL);

    // Display the error message.
    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
                                      (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
                    LocalSize(lpDisplayBuf) / sizeof(TCHAR),
                    TEXT("%s failed with error %d: %s"),
                    lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    // Free error-handling buffer allocations.
    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


bool IsSpecialIPv4(PIN_ADDR IPv4)
/*
功能：识别某个IPv4地址是不是一个特殊的IPv4地址。

is_special_ip_v4
*/
{
    if (IN4_IS_ADDR_UNSPECIFIED(IPv4)) {//IN4ADDR_ANY
        //printf("UNSPECIFIED IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_LOOPBACK(IPv4)) {//127/8
        //printf("LOOPBACK IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_BROADCAST(IPv4)) {//IN4ADDR_BROADCAST
        //printf("BROADCAST IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_MULTICAST(IPv4)) {//IN4_CLASSD
        //printf("MULTICAST IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_LINKLOCAL(IPv4)) {//169.254/16
        //printf("LINKLOCAL IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_RFC1918(IPv4)) {//10/8 172.16/12 192.168/16
        //printf("RFC1918 IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_MC_LINKLOCAL(IPv4)) {//224.0.0/24
        //printf("MC_LINKLOCAL IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_MC_ADMINLOCAL(IPv4)) {//239.255/16
        //printf("MC_ADMINLOCAL IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    if (IN4_IS_ADDR_MC_SITELOCAL(IPv4)) {
        //printf("MC_SITELOCAL IPv4:%s.\n", inet_ntoa(*IPv4));
        return true;
    }

    //if (IN4_IS_ADDR_6TO4ELIGIBLE(IPv4)) {
    //    printf("6TO4ELIGIBLE IPv4:%s.\n", inet_ntoa(*IPv4));
    //    return true;
    //}

    return false;
}


int GetOneAddress(_In_ const char * source,
                  PIN_ADDR IPv4ddress,
                  PIN6_ADDR LinkLocalIPv6Address,
                  PIN6_ADDR GlobalIPv6Address
)
/*
功能：获取一个网卡的(最后)一个IP(v4/6)地址。

参考：npcap-sdk-1.07\Examples-remote\iflist\iflist.c
*/
{
    /* Retrieve the interfaces list */
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_if_t * alldevs;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return(1);
    }

    /* Scan the list printing every entry */
    for (pcap_if_t * d = alldevs; d; d = d->next) {
        if (_stricmp(d->name, source) == 0) {
            for (pcap_addr_t * a = d->addresses; a; a = a->next) {
                switch (a->addr->sa_family) {
                case AF_INET:
                {
                    if (IPv4ddress) {
                        IPv4ddress->S_un.S_addr = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
                    }

                    break;
                }
                case AF_INET6:
                {
                    struct sockaddr_in6 * ipv6 = (struct sockaddr_in6 *)a->addr;

                    if (LinkLocalIPv6Address) {
                        if (IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr)) {
                            RtlCopyMemory(LinkLocalIPv6Address->u.Byte,
                                          ipv6->sin6_addr.u.Byte,
                                          sizeof(LinkLocalIPv6Address->u.Byte));
                        }
                    }

                    if (GlobalIPv6Address) {
                        if (IN6_IS_ADDR_GLOBAL(&ipv6->sin6_addr)) {
                            RtlCopyMemory(GlobalIPv6Address->u.Byte,
                                          ipv6->sin6_addr.u.Byte,
                                          sizeof(GlobalIPv6Address->u.Byte));
                        }
                    }

                    break;
                }
                default:
                    printf("\tAddress Family Name: Unknown\n");
                    break;
                }
            }
        }
    }

    pcap_freealldevs(alldevs);

    return 1;
}


int GetMacAddress(_In_ const char * source, OUT PBYTE MacAddress)
/*
功能:获取指定网卡的MAC地址。

改编自：npcap-sdk-1.07\Examples-remote\PacketDriver\GetMacAddress\GetMacAddress.c

注释：
npcap-sdk-1.07版本传入的格式是：rpcap://\Device\NPF_{ED5A05B0-92BC-49F5-9ACC-6E14C9665559}
npcap-sdk-1.13版本传入的格式是：\Device\NPF_{ED5A05B0-92BC-49F5-9ACC-6E14C9665559}
*/
{
    const char * str = "rpcap://";

    PSTR tmp = StrStrIA(source, str);
    if (tmp != source) {

        return 0;
    }

    tmp += lstrlenA(str);

    // Open the selected adapter
    LPADAPTER lpAdapter = PacketOpenAdapter((PCHAR)tmp);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        printf("Unable to open the adapter, Error Code : %lx\n", GetLastError());
        return -1;
    }

    // Allocate a buffer to get the MAC adress
    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL) {
        printf("error allocating memory!\n");
        PacketCloseAdapter(lpAdapter);
        return -1;
    }

    // Retrieve the adapter MAC querying the NIC driver
    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;
    ZeroMemory(OidData->Data, 6);
    if (PacketRequest(lpAdapter, FALSE, OidData)) {
        //printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
        //	   (OidData->Data)[0],
        //	   (OidData->Data)[1],
        //	   (OidData->Data)[2],
        //	   (OidData->Data)[3],
        //	   (OidData->Data)[4],
        //	   (OidData->Data)[5]);
        RtlCopyMemory(MacAddress, OidData->Data, 6);
    } else {
        printf("error retrieving the MAC address of the adapter!\n");
    }

    free(OidData);
    PacketCloseAdapter(lpAdapter);
    return (0);
}


void GetInterfaceFlagString(bpf_u_int32 flags, string & InterfaceFlagString)
{
    if (FlagContain(flags, PCAP_IF_LOOPBACK)) {
        InterfaceFlagString += " LOOPBACK;";
    }

    if (FlagContain(flags , PCAP_IF_UP)) {
        InterfaceFlagString += " UP;";
    }

    if (FlagContain(flags, PCAP_IF_RUNNING)) {
        InterfaceFlagString += " RUNNING;";
    }

    if (FlagContain(flags, PCAP_IF_WIRELESS)) {
        InterfaceFlagString += " WIRELESS;";
    }

    if (FlagContain(flags, PCAP_IF_CONNECTION_STATUS)) {
        InterfaceFlagString += " CONNECTION_STATUS;";
    }

    if (!flags) {
        if (FlagContain(flags, PCAP_IF_CONNECTION_STATUS_UNKNOWN)) {
            InterfaceFlagString += " CONNECTION_STATUS_UNKNOWN;";
        }
    }

    if (FlagContain(flags, PCAP_IF_CONNECTION_STATUS_CONNECTED)) {
        InterfaceFlagString += " CONNECTION_STATUS_CONNECTED;";
    }

    if (FlagContain(flags, PCAP_IF_CONNECTION_STATUS_DISCONNECTED)) {
        InterfaceFlagString += " CONNECTION_STATUS_DISCONNECTED;";
    }

    if (FlagContain(flags, PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE)) {
        InterfaceFlagString += " CONNECTION_STATUS_NOT_APPLICABLE;";
    }
}


char * iptos(u_long in)
/*
From tcptraceroute, convert a numeric IP address to a string
*/
#define IPTOSBUFFERS	12
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char * p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    _snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}


char * ip6tos(struct sockaddr * sockaddr, char * address, int addrlen)
/*
此函数不适用于有IPv6地址，但是没有IPv6(广域)网络的情况。
*/
{
    socklen_t sockaddrlen;

#ifdef _WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if (getnameinfo(sockaddr,
                    sockaddrlen,
                    address,
                    addrlen,
                    NULL,
                    0,
                    NI_NUMERICHOST) != 0) address = NULL;

    return address;
}


int EnumAvailableInterface()
/*
功能：列举所有可用的网卡（接口）。

参考：npcap-sdk-1.07\Examples-remote\iflist\iflist.c
*/
{
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_if_t * alldevs;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return(1);
    }

    for (pcap_if_t * d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED) {
            continue;
        }

        if (d->flags & PCAP_IF_LOOPBACK) {
            continue;
        }

        if (NULL == d->addresses) {
            continue;
        }

        string InterfaceFlagString;
        GetInterfaceFlagString(d->flags, InterfaceFlagString);

        printf("name:%s\n", d->name);
        printf("description:%s\n", d->description);
        printf("flags:%d, %s\n", d->flags, InterfaceFlagString.c_str());

        UINT8 SrcMac[6] = {0};
        GetMacAddress(d->name, SrcMac);
        printf("\tMAC: %02X-%02X-%02X-%02X-%02X-%02X\n",
               SrcMac[0], SrcMac[1], SrcMac[2], SrcMac[3], SrcMac[4], SrcMac[5]);

        for (pcap_addr_t * a = d->addresses; a; a = a->next) {
            switch (a->addr->sa_family) {
            case AF_INET:
                if (a->addr)
                    printf("\tIPv4: %s\t", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("\tNetmask: %s\t", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("\tBroadcast: %s\t", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("\tDestination: %s\t", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                printf("\n");
                break;
            case AF_INET6:
                if (a->addr) {
                    wchar_t SrcIp[46];
                    PSOCKADDR_IN6_LH sa_in6 = (PSOCKADDR_IN6_LH)a->addr;
                    InetNtop(AF_INET6, &sa_in6->sin6_addr, SrcIp, _ARRAYSIZE(SrcIp));
                    printf("\tIPv6: %ls\n", SrcIp);
                }
                break;
            default:
                printf("\tAddress Family Name: Unknown\n");
                break;
            }
        }

        printf("\n");
    }

    pcap_freealldevs(alldevs);

    return 1;
}


void GetAdapterNames()
/*
功能：打印所有的网卡的名字（不带rpcap://前缀的）。

参考：\npcap-sdk-1.13\examples-remote\PacketDriver\GetMacAddress\GetMacAddress.c
*/
{
    char		AdapterName[8192]{};
    ULONG		AdapterLength = sizeof(AdapterName);

    if (PacketGetAdapterNames(AdapterName, &AdapterLength) == FALSE) {
        printf("Unable to retrieve the list of the adapters!\n");
        return;
    }

    list<string> AdapterNames;

    for (char * tmp = AdapterName; lstrlenA(tmp); tmp += lstrlenA(tmp) + 1) {
        AdapterNames.push_back(tmp);
    }

    for (auto it : AdapterNames) {
        printf("name:%s.\r\n", it.c_str());
    }
}


bool GetFirstAvailableInterface(string & name)
/*
功能：获取第一个可用的网卡/接口的名字。

参考：EnumAvailableInterface

注释：
npcap-sdk-1.07版本传入的格式是：rpcap://\Device\NPF_{ED5A05B0-92BC-49F5-9ACC-6E14C9665559}
npcap-sdk-1.13版本传入的格式是：\Device\NPF_{ED5A05B0-92BC-49F5-9ACC-6E14C9665559}
*/
{
    bool ret = false;
    const char * str = "rpcap://";

    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_if_t * alldevs;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

    for (pcap_if_t * d = alldevs; d; d = d->next) {
        if (d->flags & PCAP_IF_CONNECTION_STATUS_DISCONNECTED) {
            continue;
        }

        if (d->flags & PCAP_IF_LOOPBACK) {
            continue;
        }

        if (NULL == d->addresses) {
            continue;
        }

        PSTR tmp = StrStrIA(d->name, str);
        _ASSERTE(tmp == d->name);

        tmp += lstrlenA(str);

        //name += d->name;
        name += tmp;

        ret = true;

        break;
    }

    pcap_freealldevs(alldevs);

    return ret;
}


int GetActivityAdapter(string & ActivityAdapter)
/*
功能：获取默认可用的网卡。

获取办法：有网关的即可。
*/
{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;

    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return 1;
    }

    // Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)MALLOC(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return 1;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            IN_ADDR ipv4{};
            if (InetPtonA(AF_INET, pAdapter->GatewayList.IpAddress.String, &ipv4)) {
                if (ipv4.S_un.S_addr) {
                    CHAR Buf[MAX_PATH]{};//\Device\NPF_{B584E80F-CD24-4D0C-895C-6A4381873E57}
                    wsprintfA(Buf, "\\Device\\NPF_%s", pAdapter->AdapterName);
                    ActivityAdapter = Buf;
                    fprintf(stderr, "选定的网卡:%s.\r\n", pAdapter->Description);
                    break;
                }
            }

            pAdapter = pAdapter->Next;
        }
    } else {
        printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
    }

    if (pAdapterInfo)
        FREE(pAdapterInfo);

    return 0;
}
