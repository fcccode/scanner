#include "ip.h"
#include "arp.h"
#include "icmp.h"


#pragma warning(disable:6255) //_alloca 通过引发堆栈溢出异常来指示失败。 应考虑改用 _malloca。


int _cdecl ip(_In_ int argc, _In_reads_(argc) WCHAR * argv[])
{
    int ret = ERROR_SUCCESS;

    if (1 == argc) {
        return Usage(argv[0]);
    }

    if (lstrcmpi(argv[1], L"arp") == 0) {
        switch (argc) {
        case 4:
        {
            USES_CONVERSION;
            char * IPv4 = W2A(argv[2]);
            _ASSERTE(IPv4);
            ret = ArpScan(inet_addr(IPv4), (BYTE)_wtoi(argv[3]));
            break;
        }
        default:
            ret = Usage(argv[0]);
            break;
        }
    } else if (lstrcmpi(argv[1], L"icmp") == 0) {

    } else {
        ret = Usage(argv[0]);
    }

    return ret;
}
