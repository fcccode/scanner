#include "arp.h"


void GetMacOfIPv4(IPAddr DestIp, IPAddr SrcIp)
{
    DWORD dwRetVal;
    ULONG MacAddr[2];       /* for 6-byte hardware addresses */
    ULONG PhysAddrLen = 6;  /* default to length of six bytes */

    memset(&MacAddr, 0xff, sizeof(MacAddr));

    IN_ADDR IPv4;
    IPv4.S_un.S_addr = DestIp;

    dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
    if (dwRetVal == NO_ERROR) {
        BYTE * bPhysAddr = (BYTE *)&MacAddr;
        if (PhysAddrLen) {
            printf("IPv4:%s. MAC:", inet_ntoa(IPv4));

            for (unsigned int i = 0; i < (int)PhysAddrLen; i++) {
                if (i == (PhysAddrLen - 1))
                    printf("%.2X\n", (int)bPhysAddr[i]);
                else
                    printf("%.2X-", (int)bPhysAddr[i]);
            }
        } else {
            printf("Warning: IPv4:%s SendArp completed successfully, but returned length=0\n", inet_ntoa(IPv4));
        }
    } else {
        printf("Error: IPv4:%s, SendArp failed with error: %d", inet_ntoa(IPv4), dwRetVal);
        switch (dwRetVal) {
        case ERROR_GEN_FAILURE:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_INVALID_PARAMETER:
            printf(" (ERROR_INVALID_PARAMETER)\n");
            break;
        case ERROR_INVALID_USER_BUFFER:
            printf(" (ERROR_INVALID_USER_BUFFER)\n");
            break;
        case ERROR_BAD_NET_NAME:
            printf(" (ERROR_GEN_FAILURE)\n");
            break;
        case ERROR_BUFFER_OVERFLOW:
            printf(" (ERROR_BUFFER_OVERFLOW)\n");
            break;
        case ERROR_NOT_FOUND:
            printf(" (ERROR_NOT_FOUND)\n");
            break;
        default:
            printf("\n");
            break;
        }
    }
}


void ArpScan(DWORD start, BYTE mask)
{
    _ASSERTE(mask <= 32);

    IN_ADDR IPv4;
    IPv4.S_un.S_addr = start;

    //////////////////////////////////////////////////////////////////////////////////////////////
    /*
    （根据mask）生成子网掩码。
    生成的步骤/思路：
    1.把子网掩码后面的0变为1.
    2.再取反。
    3.再转换为网络序。
    */

    IN_ADDR Mask;
    Mask.S_un.S_addr = 0;

    for (char x = 0; x < (32 - mask); x++) {
        ULONG t = 1 << x;
        Mask.S_un.S_addr |= t;
    }

    Mask.S_un.S_addr = ~Mask.S_un.S_addr;

    Mask.S_un.S_addr = ntohl(Mask.S_un.S_addr);

    wchar_t buffer[46] = {0};
    InetNtop(AF_INET, &Mask, buffer, _ARRAYSIZE(buffer));
    printf("mask:%ls\n", buffer);

    //////////////////////////////////////////////////////////////////////////////////////////////
    //计算起始/基础地址。

    IN_ADDR base;
    base.S_un.S_addr = IPv4.S_un.S_addr & Mask.S_un.S_addr;

    wchar_t Base[46] = {0};
    InetNtop(AF_INET, &base, Base, _ARRAYSIZE(Base));
    printf("BaseAddr:%ls\n", Base);

    //////////////////////////////////////////////////////////////////////////////////////////////
    //打印信息。

    UINT64 numbers = (UINT64)1 << (32 - mask);//必须是64位，否则可能整数溢出。

    printf("IPv4的子网掩码位数：%d\n", mask);
    printf("IPv4地址个数（包括特殊地址）：%I64d\n", numbers);
    printf("\n");

    for (ULONG i = 0; i < numbers; i++) {
        IN_ADDR temp;
        temp.S_un.S_addr = base.S_un.S_addr + ntohl(i);

        //wchar_t buf[46] = {0};
        //InetNtop(AF_INET, &temp, buf, _ARRAYSIZE(buf));
        //printf("%ls\n", buf);

        GetMacOfIPv4(temp.S_un.S_addr, 0);
    }
}
