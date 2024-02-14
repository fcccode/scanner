#pragma once

#pragma warning(disable:28251)
#pragma warning(disable:28301)


/////////////////////////////////////////////////////////////////////////////////////////////////
//一些系统的头文件和库的包含。


//#define _WIN32_WINNT 0x0501

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN // 从 Windows 头文件中排除极少使用的内容
//#define INITGUID

#ifndef UNICODE
#define UNICODE
#endif

#include <Winsock2.h>
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <crtdbg.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <fltuser.h>
#include <locale.h>
#include <Lmserver.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <aclapi.h>
#include <VersionHelpers.h>
#include <ShlDisp.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
#include <WinUser.h>
#include <direct.h>
#include <sddl.h>
#include <ws2tcpip.h>
#include <fwpsu.h>
#include <mbnapi.h>
#include <iostream>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#define _WS2DEF_
#include <mstcpip.h>
#include <Intshcut.h>
//#include <winternl.h>
//#include <SubAuth.h>
//#include <NTSecAPI.h>
//#include <ntdef.h>
//#include <netioapi.h>
//#include <LsaLookup.h>
#include <netiodef.h>
#include <comutil.h>
#include <wbemidl.h>
#include <dbt.h>
#include <lm.h> //内含lmaccess.h。
#include <winnetwk.h>
#include <ws2spi.h>
#include <comdef.h>
#include <wtypes.h>
#include <af_irda.h>
#include <mshtmhst.h>
#include <exdisp.h>
#include <memory.h>

#define _CRT_RAND_S 
#include <stdlib.h>

#ifndef INITGUID
#define INITGUID
#include <guiddef.h>
#undef INITGUID
#else
#include <guiddef.h>
#endif

#include <atlstr.h>
#include <atlbase.h>
#include <atlcomcli.h>
#include <atlconv.h>

#include <iptypes.h>
#include "tdiinfo.h"
//#include <..\km\tdistat.h>
#include "tcpioctl.h"

#include <initguid.h> //注意前后顺序。静态定义UUID用的，否则：error LNK2001。
#include <usbioctl.h>
#include <usbiodef.h>
//#include <usbctypes.h>
#include <intsafe.h>
#include <specstrings.h>
#include <usb.h>
#include <usbuser.h>

#include <wincon.h> 
#include <time.h> 
//#include <fwpmu.h>
#include <conio.h>
#include <nb30.h>

#pragma comment(lib, "fwpuclnt.lib") 
#pragma comment(lib, "Rpcrt4.lib")

#pragma comment(lib, "mpr.lib")

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Version.lib") 
//#pragma comment (lib,"Url.lib")
#pragma comment(lib, "wbemuuid.lib")

#include <urlmon.h>
#pragma comment (lib,"Urlmon.lib")

#include <Wlanapi.h>
#pragma comment (lib, "Wlanapi.lib")

#include <bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

#include <shellapi.h>
#pragma comment (lib, "Shell32.lib")

#include <ncrypt.h>
#pragma comment (lib, "Ncrypt.lib")

#include <wintrust.h>
#pragma comment (lib, "wintrust.lib")

#include <Setupapi.h>
#pragma comment (lib,"Setupapi.lib")

#include <Shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

#include <DbgHelp.h>
#pragma comment (lib,"DbgHelp.lib")

#include <psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <Sfc.h>
#pragma comment(lib, "Sfc.lib")

//#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

#pragma comment(lib,"Netapi32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <Sensapi.h>
#pragma comment (lib,"Sensapi.lib")

#include <string>
#include <list>
#include <regex>
#include <map>
#include <set>

using namespace std;


#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap.h> 
#include <Packet32.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")


#include "..\lib\libnet\inc\libnet.h"
#pragma comment(lib, "libnet.lib")


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifndef FlagContain
#define FlagContain(_F,_SF)        ((BOOLEAN)(((_F) & (_SF)) == (_SF)))
#endif


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
//其实：IPV4的只需This buffer should be large enough to hold at least 16 characters.
#define MAX_ADDRESS_STRING_LENGTH   64


//十进制的端口字符串的长度。其实最大长度是5，可以设置为8。
#define MAX_PORT_STRING_LENGTH  5  //65535==FFFF 


//IPv4的单字符版的正则表达式。
#define IPV4_REGULAR R"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4的宽字符版的正则表达式。
#define IPV4_REGULARW LR"((\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3})(\.)(\d{1,3}))"  


//IPv4子网掩码的单字符版的正则表达式。
#define IPV4SUBNET_REGULAR (IPV4_REGULAR R"(/(\d{1,5}))")


//IPv4子网掩码的宽字符版的正则表达式。
#define IPV4SUBNET_REGULARW (IPV4_REGULARW LR"(/(\d{1,5}))")


#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


//////////////////////////////////////////////////////////////////////////////////////////////////


extern CHAR g_ExePath[MAX_PATH];
extern CHAR g_Date[MAX_PATH];

BOOL LoadNpcapDlls();
int RangedRand(int range_min, int range_max);
void ErrorHandler(LPTSTR lpszFunction);
bool IsSpecialIPv4(PIN_ADDR IPv4);
int GetMacAddress(_In_ const char * source, OUT PBYTE MacAddress);
int GetOneAddress(_In_ const char * source,
				  PIN_ADDR IPv4ddress,
				  PIN6_ADDR LinkLocalIPv6Address,
				  PIN6_ADDR GlobalIPv6Address);
int EnumAvailableInterface();
void GetAdapterNames();
bool GetFirstAvailableInterface(string & name);
int GetActivityAdapter(string & ActivityAdapter);
void GetExePath(_Out_writes_(cchDest) STRSAFE_LPSTR pszDest, _In_ size_t cchDest);
ADDRESS_FAMILY GetFamilyByIpStr(const char * ip);

int Usage(TCHAR * exe);