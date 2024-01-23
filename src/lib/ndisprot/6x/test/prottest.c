#include "raw.h"
#include "prottest.h"

#pragma warning(disable:4201)   // nameless struct/union
#pragma warning(disable:4127)   // conditional expression is constant

CHAR            g_Device[] = "\\\\.\\\\NdisProt";
CHAR * g_pDevice = &g_Device[0];

BOOLEAN         g_DoEnumerate = FALSE;
BOOLEAN         g_DoReads = FALSE;
INT             g_NumberOfPackets = -1;
ULONG           g_PacketLength = 100;
UCHAR           g_SrcMacAddr[MAC_ADDR_LEN];
UCHAR           g_DstMacAddr[MAC_ADDR_LEN];
BOOLEAN         g_bDstMacSpecified = FALSE;
CHAR * g_pNdisDeviceName = "JUNK";
USHORT          g_EthType = 0x8e88;
BOOLEAN         g_bUseFakeAddress = FALSE;
UCHAR           g_FakeSrcMacAddr[MAC_ADDR_LEN] = {0};


VOID PrintUsage()
{
    PRINTF(("usage: PROTTEST [options] <devicename>\n"));
    PRINTF(("options:\n"));
    PRINTF(("       -e: Enumerate devices\n"));
    PRINTF(("       -r: Read\n"));
    PRINTF(("       -w: Write (default)\n"));
    PRINTF(("       -l <length>: length of each packet (default: %d)\n", g_PacketLength));
    PRINTF(("       -n <count>: number of packets (defaults to infinity)\n"));
    PRINTF(("       -m <MAC address> (defaults to local MAC)\n"));
    PRINTF(("       -f Use a fake address to send out the packets.\n"));
}


BOOL GetOptions(INT argc, _In_reads_(argc + 1) CHAR * argv[])
{
    INT         i;
    CHAR * pOption;
    ULONG       DstMacAddrUlong[MAC_ADDR_LEN];
    INT         RetVal;
    PCSTR       Parameter;

    if (argc < 2) {
        PRINTF(("Missing <devicename> argument\n"));
        return FALSE;
    }

    do {
        for (i = 1; i < argc; i++) {
            pOption = argv[i];

            if ((*pOption == '-') || (*pOption == '/')) {
                pOption++;
                if (*pOption == '\0') {
                    DEBUGP(("Badly formed option\n"));
                    return (FALSE);
                }
            } else {
                break;
            }

            if (i < argc - 2) {
                Parameter = argv[i + 1];
            } else {
                Parameter = NULL;
            }

            switch (*pOption) {
            case 'e':
                g_DoEnumerate = TRUE;
                break;
            case 'f':
                g_bUseFakeAddress = TRUE;
                break;
            case 'r':
                g_DoReads = TRUE;
                break;
            case 'w':
                g_DoReads = FALSE;
                break;
            case 'l':
                if (Parameter != NULL) {
                    RetVal = atoi(Parameter);
                    if (RetVal != 0) {
                        g_PacketLength = RetVal;
                        DEBUGP((" Option: g_PacketLength = %d\n", g_PacketLength));
                        i++;
                        break;
                    }
                }
                PRINTF(("Option l needs g_PacketLength parameter\n"));
                return (FALSE);
            case 'n':
                if (Parameter != NULL) {
                    RetVal = atoi(Parameter);
                    if (RetVal != 0) {
                        g_NumberOfPackets = RetVal;
                        DEBUGP((" Option: g_NumberOfPackets = %d\n", g_NumberOfPackets));
                        i++;
                        break;
                    }
                }
                PRINTF(("Option n needs g_NumberOfPackets parameter\n"));
                return (FALSE);
            case 'm':
                if (Parameter != NULL) {
                    RetVal = sscanf_s(Parameter, "%2x:%2x:%2x:%2x:%2x:%2x",
                                      &DstMacAddrUlong[0],
                                      &DstMacAddrUlong[1],
                                      &DstMacAddrUlong[2],
                                      &DstMacAddrUlong[3],
                                      &DstMacAddrUlong[4],
                                      &DstMacAddrUlong[5]);

                    if (RetVal == 6) {
                        for (INT j = 0; j < MAC_ADDR_LEN; j++) {
                            g_DstMacAddr[j] = (UCHAR)DstMacAddrUlong[j];
                        }

                        DEBUGP((" Option: Dest MAC Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                g_DstMacAddr[0],
                                g_DstMacAddr[1],
                                g_DstMacAddr[2],
                                g_DstMacAddr[3],
                                g_DstMacAddr[4],
                                g_DstMacAddr[5]));
                        g_bDstMacSpecified = TRUE;

                        i++;
                        break;
                    }
                }

                PRINTF(("Option m needs MAC address parameter\n"));
                return (FALSE);
            case '?':
                return (FALSE);
            default:
                PRINTF(("Unknown option %c\n", *pOption));
                return (FALSE);
            }
        }

        g_pNdisDeviceName = argv[i];
    } while (FALSE);

    return TRUE;
}


HANDLE OpenHandle(_In_ PSTR pDeviceName)
{
    DWORD   DesiredAccess = GENERIC_READ | GENERIC_WRITE;
    DWORD   ShareMode = 0;
    LPSECURITY_ATTRIBUTES   lpSecurityAttributes = NULL;
    DWORD   CreationDistribution = OPEN_EXISTING;
    DWORD   FlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;    

    HANDLE Handle = CreateFileA(pDeviceName,
                         DesiredAccess,
                         ShareMode,
                         lpSecurityAttributes,
                         CreationDistribution,
                         FlagsAndAttributes,
                         NULL);
    if (Handle == INVALID_HANDLE_VALUE) {
        DEBUGP(("Creating file failed, error %x\n", GetLastError()));
        return Handle;
    }

    //  Wait for the driver to finish binding.
    DWORD   BytesReturned;
    if (!DeviceIoControl(Handle,
                         IOCTL_BIND_WAIT,
                         NULL,
                         0,
                         NULL,
                         0,
                         &BytesReturned,
                         NULL)) {
        DEBUGP(("IOCTL_NDISIO_BIND_WAIT failed, error %x\n", GetLastError()));
        CloseHandle(Handle);
        Handle = INVALID_HANDLE_VALUE;
    }

    return (Handle);
}


BOOL OpenNdisDevice(_In_ HANDLE Handle, _In_ PCSTR pDeviceName)
{
    _ASSERTE(pDeviceName);

    WCHAR   wNdisDeviceName[MAX_NDIS_DEVICE_NAME_LEN];
    SIZE_T  NameLength = strlen(pDeviceName);    
    SIZE_T  i;

    // Convert to unicode string - non-localized...
    INT wNameLength = 0;
    for (i = 0; i < NameLength && i < MAX_NDIS_DEVICE_NAME_LEN - 1; i++) {
        wNdisDeviceName[i] = (WCHAR)pDeviceName[i];
        wNameLength++;
    }
    wNdisDeviceName[i] = L'\0';

    DEBUGP(("Trying to access NDIS Device: %ws\n", wNdisDeviceName));

    DWORD   BytesReturned;
    return (DeviceIoControl(Handle,
                            IOCTL_OPEN_DEVICE,
                            (LPVOID)&wNdisDeviceName[0],
                            wNameLength * sizeof(WCHAR),
                            NULL,
                            0,
                            &BytesReturned,
                            NULL));
}


_Success_(return)
BOOL GetSrcMac(_In_ HANDLE  Handle, _Out_writes_bytes_(MAC_ADDR_LEN) PUCHAR  pSrcMacAddr)
{
    DWORD       BytesReturned;
    BOOLEAN     bSuccess;
    UCHAR       QueryBuffer[sizeof(QUERY_OID) + MAC_ADDR_LEN];
    PQUERY_OID  pQueryOid;

    DEBUGP(("Trying to get src mac address\n"));

    pQueryOid = (PQUERY_OID)&QueryBuffer[0];
    pQueryOid->Oid = OID_802_3_CURRENT_ADDRESS;
    pQueryOid->PortNumber = 0;

    bSuccess = (BOOLEAN)DeviceIoControl(Handle,
                                        IOCTL_QUERY_OID_VALUE,
                                        (LPVOID)&QueryBuffer[0],
                                        sizeof(QueryBuffer),
                                        (LPVOID)&QueryBuffer[0],
                                        sizeof(QueryBuffer),
                                        &BytesReturned,
                                        NULL);
    if (bSuccess) {
        DEBUGP(("GetSrcMac: IoControl success, BytesReturned = %d\n", BytesReturned));

#pragma warning(suppress:6202) // buffer overrun warning - enough space allocated in QueryBuffer
        memcpy(pSrcMacAddr, pQueryOid->Data, MAC_ADDR_LEN);
    } else {
        DEBUGP(("GetSrcMac: IoControl failed: %d\n", GetLastError()));
    }

    return (bSuccess);
}


VOID DoReadProc(HANDLE  Handle)
{
    PUCHAR      pReadBuf = NULL;
    INT         ReadCount = 0;
    BOOLEAN     bSuccess;
    ULONG       BytesRead;

    DEBUGP(("DoReadProc\n"));

    do {
        pReadBuf = malloc(g_PacketLength);
        if (pReadBuf == NULL) {
            PRINTF(("DoReadProc: failed to alloc %d bytes\n", g_PacketLength));
            break;
        }

        ReadCount = 0;
        while (TRUE) {
            bSuccess = (BOOLEAN)ReadFile(Handle, (LPVOID)pReadBuf, g_PacketLength, &BytesRead, NULL);
            if (!bSuccess) {
                PRINTF(("DoReadProc: ReadFile failed on Handle %p, error %x\n", Handle, GetLastError()));
                break;
            }
            ReadCount++;

            DEBUGP(("DoReadProc: read pkt # %d, %d bytes\n", ReadCount, BytesRead));

            if ((g_NumberOfPackets != -1) && (ReadCount == g_NumberOfPackets)) {
                break;
            }
        }
    } while (FALSE);

    if (pReadBuf) {
        free(pReadBuf);
    }

    PRINTF(("DoReadProc finished: read %d packets\n", ReadCount));
}


VOID DoWriteProc(HANDLE  Handle)
{
    PUCHAR      pWriteBuf = NULL;
    INT         SendCount = 0;    

    DEBUGP(("DoWriteProc\n"));

    do {
        pWriteBuf = malloc(g_PacketLength);
        if (pWriteBuf == NULL) {
            DEBUGP(("DoWriteProc: Failed to malloc %d bytes\n", g_PacketLength));
            break;
        }
        PETH_HEADER pEthHeader = (PETH_HEADER)pWriteBuf;
        pEthHeader->EthType = g_EthType;

        if (g_bUseFakeAddress) {
            memcpy(pEthHeader->SrcAddr, g_FakeSrcMacAddr, MAC_ADDR_LEN);
        } else {
            memcpy(pEthHeader->SrcAddr, g_SrcMacAddr, MAC_ADDR_LEN);
        }

        memcpy(pEthHeader->DstAddr, g_DstMacAddr, MAC_ADDR_LEN);

        PUCHAR pData = (PUCHAR)(pEthHeader + 1);
        for (UINT i = 0; i < g_PacketLength - sizeof(ETH_HEADER); i++) {
            *pData++ = (UCHAR)i;
        }

        SendCount = 0;

        while (TRUE) {
            DWORD BytesWritten;
            BOOLEAN bSuccess = (BOOLEAN)WriteFile(Handle, pWriteBuf, g_PacketLength, &BytesWritten, NULL);
            if (!bSuccess) {
                PRINTF(("DoWriteProc: WriteFile failed on Handle %p\n", Handle));
                break;
            }
            SendCount++;

            DEBUGP(("DoWriteProc: sent %d bytes\n", BytesWritten));

            if ((g_NumberOfPackets != -1) && (SendCount == g_NumberOfPackets)) {
                break;
            }
        }
    } while (FALSE);

    if (pWriteBuf) {
        free(pWriteBuf);
    }

    PRINTF(("DoWriteProc: finished sending %d packets of %d bytes each\n", SendCount, g_PacketLength));
}


VOID EnumerateDevices(HANDLE  Handle)
{
    typedef __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) QueryBindingCharBuf;
    QueryBindingCharBuf	Buf[1024] = {0};
    DWORD       		BufLength = sizeof(Buf);
    DWORD       		BytesWritten;
    DWORD       		i = 0;
    PQUERY_BINDING 	    pQueryBinding = (PQUERY_BINDING)Buf;

    for (pQueryBinding->BindingIndex = i; /* NOTHING */; pQueryBinding->BindingIndex = ++i) {
        if (DeviceIoControl(Handle,
                            IOCTL_QUERY_BINDING,
                            pQueryBinding,
                            sizeof(QUERY_BINDING),
                            Buf,
                            BufLength,
                            &BytesWritten,
                            NULL)) {
            PRINTF(("%2d. %ws\n     - %ws\n",
                    pQueryBinding->BindingIndex,
                    (WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceNameOffset),
                    (WCHAR *)((PUCHAR)pQueryBinding + pQueryBinding->DeviceDescrOffset)));

            memset(Buf, 0, BufLength);
        } else {
            ULONG   rc = GetLastError();
            if (rc != ERROR_NO_MORE_ITEMS) {
                PRINTF(("EnumerateDevices: terminated abnormally, error %d\n", rc));
            }
            break;
        }
    }
}


VOID __cdecl main(INT argc, _In_reads_(argc + 1) LPSTR * argv)
{
    HANDLE DeviceHandle = INVALID_HANDLE_VALUE;

    __debugbreak();//DebugBreak();

    do {
        if (!GetOptions(argc, argv)) {
            PrintUsage();
            break;
        }

        DeviceHandle = OpenHandle(g_pDevice);
        if (DeviceHandle == INVALID_HANDLE_VALUE) {
            PRINTF(("Failed to open %s\n", g_pDevice));
            break;
        }

        if (g_DoEnumerate) {
            EnumerateDevices(DeviceHandle);
            break;
        }

        if (!OpenNdisDevice(DeviceHandle, g_pNdisDeviceName)) {
            PRINTF(("Failed to access %s\n", g_pNdisDeviceName));
            break;
        }

        DEBUGP(("Opened device %s successfully!\n", g_pNdisDeviceName));

        if (!GetSrcMac(DeviceHandle, g_SrcMacAddr)) {
            PRINTF(("Failed to obtain local MAC address\n"));
            break;
        }

        DEBUGP(("Got local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                g_SrcMacAddr[0],
                g_SrcMacAddr[1],
                g_SrcMacAddr[2],
                g_SrcMacAddr[3],
                g_SrcMacAddr[4],
                g_SrcMacAddr[5]));

        if (!g_bDstMacSpecified) {
            memcpy(g_DstMacAddr, g_SrcMacAddr, MAC_ADDR_LEN);
        }

        if (g_DoReads) {
            //DoReadProc(DeviceHandle);
        } else {
            //DoWriteProc(DeviceHandle);
            raw(DeviceHandle);
            //DoReadProc(DeviceHandle);
        }
    } while (FALSE);

    if (DeviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(DeviceHandle);
    }
}
