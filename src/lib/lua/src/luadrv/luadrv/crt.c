/*
说明：这里是CRT的内核实现。

现在这里的函数实现大多为空，需要自己编写代码实现。
*/


#include "crt.h"
#include "pch.h"
#include "fpu.h"
#include "file.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


int * __cdecl _errno(void)
{
    return 0;
}


__declspec(noalias)
_Check_return_ _CRT_INSECURE_DEPRECATE(sscanf_s)
_CRT_STDIO_INLINE
int __CRTDECL _sscanf(
    _In_z_                       char const * const _Buffer,
    _In_z_ _Scanf_format_string_ char const * const _Format,
    ...
)
{
    int _Result = 0;
    va_list _ArgList;
    __crt_va_start(_ArgList, _Format);

    //_Result = _vsscanf_l(_Buffer, _Format, NULL, _ArgList);
    _Result = sscanf_s(_Buffer, _Format, _ArgList);

    __crt_va_end(_ArgList);
    return _Result;
}


//_Check_return_
//_ACRTIMP double __cdecl strtod(
//    _In_z_                   char const * _String,
//    _Out_opt_ _Deref_post_z_ char ** _EndPtr
//) 
double __cdecl strtod(const char * strSource, char ** endptr)
/*
需要自己实现，驱动一般不用浮点数。
要用浮点数还得一些特殊的代码技巧。

参考：\Win2K3\NT\base\crts\crtw32\convert\strtod.c
*/
{
    UNREFERENCED_PARAMETER(strSource);
    UNREFERENCED_PARAMETER(endptr);

    return 0;
}


__declspec(noalias)
_ACRTIMP _CRT_HYBRIDPATCHABLE
void __cdecl free(
    _Pre_maybenull_ _Post_invalid_ void * _Block
)
{
    if (_Block) {
        ExFreePoolWithTag(_Block, TAG);
    }
}


__declspec(noalias)
//_Check_return_ _Ret_maybenull_ _Post_writable_byte_size_(_Size)
//_ACRTIMP _CRTALLOCATOR _CRT_JIT_INTRINSIC _CRTRESTRICT _CRT_HYBRIDPATCHABLE
void * __cdecl malloc(
    _In_ _CRT_GUARDOVERFLOW size_t _Size
)
{
    return ExAllocatePoolWithTag(PagedPool, _Size, TAG);
}


__declspec(noalias)
//_Success_(return != 0) _Check_return_ _Ret_maybenull_ _Post_writable_byte_size_(_Size)
//_ACRTIMP _CRTALLOCATOR _CRTRESTRICT _CRT_HYBRIDPATCHABLE
void * __cdecl realloc(
    _Pre_maybenull_ _Post_invalid_ void * _Block,
    _In_ _CRT_GUARDOVERFLOW        size_t _Size
)
{
    if (_Block) {
        ExFreePoolWithTag(_Block, TAG);
    }

    return ExAllocatePoolWithTag(PagedPool, _Size, TAG);
}


//https://docs.microsoft.com/en-us/cpp/dotnet/converting-projects-from-mixed-mode-to-pure-intermediate-language?view=msvc-160
#ifndef __FLTUSED__
#define __FLTUSED__
//extern "C" __declspec(selectany) int _fltused = 1;
__declspec(selectany) int _fltused = 1;
#endif


__declspec(noalias)
_Success_(return >= 0)
_Check_return_opt_
//_CRT_STDIO_INLINE 
int __CRTDECL vsnprintf(
    _Out_writes_opt_(_BufferCount) _Post_maybez_ char * const _Buffer,
    _In_                                        size_t      const _BufferCount,
    _In_z_ _Printf_format_string_               char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    //return _vsnprintf_l(_Buffer, _BufferCount, _Format, NULL, _ArgList);

    UNREFERENCED_PARAMETER(_Buffer);
    UNREFERENCED_PARAMETER(_BufferCount);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);

    return 0;
}


__declspec(noalias)
_Check_return_
_ACRTIMP
long long __cdecl strtoll(
    _In_z_                   char const * _String,
    _Out_opt_ _Deref_post_z_ char ** _EndPtr,
    _In_                     int         _Radix
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    UNREFERENCED_PARAMETER(_String);
    UNREFERENCED_PARAMETER(_EndPtr);
    UNREFERENCED_PARAMETER(_Radix);

    return 0;
}


__declspec(noalias)
_Check_return_
_ACRTIMP
unsigned long long __cdecl strtoull(
    _In_z_                   char const * _String,
    _Out_opt_ _Deref_post_z_ char ** _EndPtr,
    _In_                     int         _Radix
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    UNREFERENCED_PARAMETER(_String);
    UNREFERENCED_PARAMETER(_EndPtr);
    UNREFERENCED_PARAMETER(_Radix);

    return 0;
}


__declspec(noalias)
_Check_return_opt_
//_CRT_STDIO_INLINE //禁止内敛，否者，使用者找不到这个函数。
int __CRTDECL fprintf(
    _Inout_                       FILE * const _Stream,
    _In_z_ _Printf_format_string_ char const * const _Format,
    ...
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    int _Result = 0;
    va_list _ArgList;
    __crt_va_start(_ArgList, _Format);

    //_Result = _vfprintf_l(_Stream, _Format, NULL, _ArgList);
    //_Result = vsprintf_s(_Stream, _Format, NULL, _ArgList);

    __crt_va_end(_ArgList);
    return _Result;
}


void * __cdecl calloc(size_t number, size_t size)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    void * ret = ExAllocatePoolWithTag(PagedPool, number * size, TAG);
    if (ret) {
        RtlZeroMemory(ret, number * size);
    }

    return ret;
}


//_Check_return_
//_CRT_STDIO_INLINE 
int __CRTDECL vscprintf(
    _In_z_ _Printf_format_string_ char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);

    return 0;
}


BOOL
__stdcall
CryptAcquireContextA(
    _Out_       HCRYPTPROV * phProv,
    _In_opt_    LPCSTR    szContainer,
    _In_opt_    LPCSTR    szProvider,
    _In_        DWORD       dwProvType,
    _In_        DWORD       dwFlags
)
/*
需要自己使用内核相关的API或算法实现，如：内核态的CNG里的routine。
*/
{
    UNREFERENCED_PARAMETER(phProv);
    UNREFERENCED_PARAMETER(szContainer);
    UNREFERENCED_PARAMETER(szProvider);
    UNREFERENCED_PARAMETER(dwProvType);
    UNREFERENCED_PARAMETER(dwFlags);

    return 0;
}


BOOL
WINAPI
CryptGenRandom(
    _In_                    HCRYPTPROV  hProv,
    _In_                    DWORD   dwLen,
    _Inout_updates_bytes_(dwLen)   BYTE * pbBuffer
)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    UNREFERENCED_PARAMETER(hProv);
    UNREFERENCED_PARAMETER(dwLen);
    UNREFERENCED_PARAMETER(pbBuffer);

    return 0;
}


BOOL
WINAPI
CryptReleaseContext(
    _In_    HCRYPTPROV  hProv,
    _In_    DWORD       dwFlags
)
/*
需要自己使用内核相关的API或算法实现，如：内核态的CNG里的routine。
*/
{
    UNREFERENCED_PARAMETER(hProv);
    UNREFERENCED_PARAMETER(dwFlags);

    return 0;
}


int __CRTDECL vprintf(
    _In_z_ _Printf_format_string_ char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);

    return 0;
}


DWORD
WINAPI
GetVersion(
    VOID
)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    return 0;
}


#pragma function(GetLastError)
DWORD
WINAPI
GetLastError(
    VOID
)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    return 0;
}


//static __inline 
time_t __CRTDECL time(_Out_opt_ time_t * const _Time)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    //return _time64(_Time);
    return 0;
}


char * __cdecl setlocale(_In_ int _Category, _In_opt_z_ const char * _Locale)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    UNREFERENCED_PARAMETER(_Category);
    UNREFERENCED_PARAMETER(_Locale);

    return 0;
}


//void __cdecl _assert(_In_z_ const char * _Message, _In_z_ const char * _File, _In_ unsigned _Line)
///*
//需要自己使用内核相关的API或算法实现。
//*/
//{
//    //ASSERT(_Message);//这个更简单。
//
//    if (!(_Message)) {
//        RtlAssert((PVOID)_Message, (PVOID)_File, _Line, NULL);
//    }
//}


void __cdecl _wassert(
    _In_z_ wchar_t const * _Message,
    _In_z_ wchar_t const * _File,
    _In_   unsigned       _Line
)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    //ASSERT(_Message);//这个更简单。

    if (!(_Message)) {
        RtlAssert((PVOID)_Message, (PVOID)_File, _Line, NULL);
    }
}


char * __cdecl getenv(_In_z_ const char * _VarName)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    UNREFERENCED_PARAMETER(_VarName);
    return 0;
}


char * __cdecl strerror(_In_ int error)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    UNREFERENCED_PARAMETER(error);
    return 0;
}


_Success_(return >= 0)
_Check_return_opt_ _CRT_INSECURE_DEPRECATE(vsprintf_s)
_CRT_STDIO_INLINE int __CRTDECL _vsprintf(
    _Pre_notnull_ _Always_(_Post_z_) char * const _Buffer,
    _In_z_ _Printf_format_string_    char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    //return _vsnprintf_l(_Buffer, (size_t)-1, _Format, NULL, _ArgList);
    UNREFERENCED_PARAMETER(_Buffer);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);
    return 0;
}


_Check_return_
_CRT_STDIO_INLINE int __CRTDECL _vscprintf(
    _In_z_ _Printf_format_string_ char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    //return _vscprintf_l(_Format, NULL, _ArgList);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);
    return 0;
}


char * __CRTDECL strpbrk(_In_z_ const char * _Str, _In_z_ const char * _Control)
{
    UNREFERENCED_PARAMETER(_Str);
    UNREFERENCED_PARAMETER(_Control);
    return 0;

    //return (char *)strpbrk((const char *)_Str, _Control);
}


#pragma function(FreeLibrary)
BOOL
WINAPI
FreeLibrary(
    _In_ HMODULE hLibModule
)
{
    UNREFERENCED_PARAMETER(hLibModule);

    return 0;
}


int __cdecl system(_In_opt_z_ const char * _Command)
{
    UNREFERENCED_PARAMETER(_Command);

    return 0;
}


size_t __cdecl strftime(_Out_writes_z_(_SizeInBytes) char * _Buf,
                        _In_ size_t _SizeInBytes,
                        _In_z_ _Printf_format_string_ const char * _Format,
                        _In_ const struct tm * _Tm
)
{
    UNREFERENCED_PARAMETER(_Buf);
    UNREFERENCED_PARAMETER(_SizeInBytes);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_Tm);

    return 0;
}


double __cdecl difftime(time_t t1, time_t t2)
{
    UNREFERENCED_PARAMETER(t1);
    UNREFERENCED_PARAMETER(t2);

    return 0;
}

struct tm * __cdecl gmtime(const time_t * x)
{
    UNREFERENCED_PARAMETER(x);

    return 0;
}

struct tm * __cdecl localtime(const time_t * x)
{
    UNREFERENCED_PARAMETER(x);

    return 0;
}

time_t __cdecl mktime(struct tm * x)
{
    UNREFERENCED_PARAMETER(x);

    return 0;
}


clock_t __cdecl clock(void)
{
    return 0;
}


int     __cdecl strcoll(_In_z_  const char * _Str1, _In_z_  const  char * _Str2)
{
    UNREFERENCED_PARAMETER(_Str1);
    UNREFERENCED_PARAMETER(_Str2);

    return 0;
}


char * __cdecl tmpnam(char * _Buf)
{
    UNREFERENCED_PARAMETER(_Buf);

    return 0;
}


#pragma function(GetProcAddress)
FARPROC
WINAPI
GetProcAddress(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName
)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpProcName);

    return 0;
}


#pragma function(GetModuleFileNameA)
DWORD
WINAPI
GetModuleFileNameA(
    _In_opt_ HMODULE hModule,
    _Out_writes_to_(nSize, ((return < nSize) ? (return +1) : nSize)) LPSTR lpFilename,
    _In_ DWORD nSize
)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpFilename);
    UNREFERENCED_PARAMETER(nSize);

    return 0;
}


#pragma function(LoadLibraryExA)
HMODULE
WINAPI
LoadLibraryExA(
    _In_ LPCSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags
)
{
    UNREFERENCED_PARAMETER(lpLibFileName);
    UNREFERENCED_PARAMETER(hFile);
    UNREFERENCED_PARAMETER(dwFlags);

    return 0;
}


#pragma function(FormatMessageA)
DWORD
WINAPI
FormatMessageA(
    _In_     DWORD dwFlags,
    _In_opt_ LPCVOID lpSource,
    _In_     DWORD dwMessageId,
    _In_     DWORD dwLanguageId,
    _When_((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0, _At_((LPSTR *)lpBuffer, _Outptr_result_z_))
    _When_((dwFlags & FORMAT_MESSAGE_ALLOCATE_BUFFER) == 0, _Out_writes_z_(nSize))
    LPSTR lpBuffer,
    _In_     DWORD nSize,
    _In_opt_ va_list * Arguments
)
{
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(lpSource);
    UNREFERENCED_PARAMETER(dwLanguageId);
    UNREFERENCED_PARAMETER(lpBuffer);
    UNREFERENCED_PARAMETER(nSize);
    UNREFERENCED_PARAMETER(Arguments);

    return 0;
}


void __cdecl longjmp(jmp_buf environment, int value)
{
    UNREFERENCED_PARAMETER(environment);
    UNREFERENCED_PARAMETER(value);

    return 0;
}


//_Check_return_opt_
//    _ACRTIMP 
int __cdecl fflush(_Inout_opt_ FILE * _Stream)
{
    UNREFERENCED_PARAMETER(_Stream);

    return 0;
}


//_CRTIMP
//    __declspec(noreturn) 
void __cdecl abort(void)
{


}


int __cdecl _setjmp3(
    OUT jmp_buf env,
    int count,
    ...
)
{
    UNREFERENCED_PARAMETER(env);
    UNREFERENCED_PARAMETER(count);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
