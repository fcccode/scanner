#include "file.h"


//////////////////////////////////////////////////////////////////////////////////////////////////



//_Check_return_opt_
//_CRT_STDIO_INLINE 
int __CRTDECL vfprintf(
    _Inout_                       FILE * const _Stream,
    _In_z_ _Printf_format_string_ char const * const _Format,
    va_list           _ArgList
)
/*
需要自己使用内核相关的API或算法实现，如：RTL系列的routine。
*/
{
    UNREFERENCED_PARAMETER(_Stream);
    UNREFERENCED_PARAMETER(_Format);
    UNREFERENCED_PARAMETER(_ArgList);

    return 0;
}


int __cdecl _open(_In_z_ const char * _Filename, _In_ int _OpenFlag, ...)
/*
需要自己使用内核相关的API或算法实现，如Zw系列的文件操作函数，不建议使用Flt系列。
尽管Flt的那个实例句柄可以为空，但这里没有阐述可传，需默认指定。
*/
{
    UNREFERENCED_PARAMETER(_Filename);
    UNREFERENCED_PARAMETER(_OpenFlag);

    return 0;
}


FILE * __cdecl fopen(_In_z_ const char * _Filename, _In_z_ const char * _Mode)
{
    UNREFERENCED_PARAMETER(_Filename);
    UNREFERENCED_PARAMETER(_Mode);

    return 0;
}


FILE * __cdecl freopen(_In_z_ const char * _Filename, _In_z_ const char * _Mode, _Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_Filename);
    UNREFERENCED_PARAMETER(_Mode);
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


int __cdecl ferror(_In_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


int __cdecl feof(_In_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


int __cdecl close(_In_ int _FileHandle)
/*
需要自己使用内核相关的API或算法实现，如Zw或Flt系列的文件操作函数。
*/
{
    return ZwClose(_FileHandle);
    //return FltClose(hFile);
}


int __cdecl fclose(_Inout_ FILE * _File)
{
    return ZwClose(_File);
    //return FltClose(hFile);
}


size_t __cdecl fread(_Out_writes_bytes_(_ElementSize * _Count) void * _DstBuf,
                     _In_ size_t _ElementSize,
                     _In_ size_t _Count,
                     _Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_DstBuf);
    UNREFERENCED_PARAMETER(_ElementSize);
    UNREFERENCED_PARAMETER(_Count);
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


int __cdecl write(_In_ int _Filehandle,
                  _In_reads_bytes_(_MaxCharCount) const void * _Buf,
                  _In_ unsigned int _MaxCharCount
)
/*
需要自己使用内核相关的API或算法实现，如Zw或Flt系列的文件操作函数。
*/
{
    UNREFERENCED_PARAMETER(_Filehandle);
    UNREFERENCED_PARAMETER(_Buf);
    UNREFERENCED_PARAMETER(_MaxCharCount);

    return 0;
}


size_t __cdecl fwrite(_In_reads_bytes_(_Size * _Count) const void * _Str,
                      _In_ size_t _Size,
                      _In_ size_t _Count,
                      _Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_Str);
    UNREFERENCED_PARAMETER(_Size);
    UNREFERENCED_PARAMETER(_Count);
    UNREFERENCED_PARAMETER(_File);
    return 0;
}


FILE * __cdecl __acrt_iob_func(unsigned _X)
/*
需要自己使用内核相关的API或算法实现。
*/
{
    UNREFERENCED_PARAMETER(_X);
    return 0;
}


int __cdecl getc(_Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);
    return 0;
}


int __cdecl fseek(_Inout_ FILE * _File, _In_ long _Offset, _In_ int _Origin)
{
    UNREFERENCED_PARAMETER(_File);
    UNREFERENCED_PARAMETER(_Offset);
    UNREFERENCED_PARAMETER(_Origin);
    return 0;
}


long __cdecl ftell(_Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


char * __cdecl fgets(_Out_writes_z_(_MaxCount) char * _Buf, _In_ int _MaxCount, _Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_Buf);
    UNREFERENCED_PARAMETER(_MaxCount);
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


int __cdecl _pclose(_Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


FILE * __cdecl _popen(_In_z_ const char * _Command, _In_z_ const char * _Mode)
{
    UNREFERENCED_PARAMETER(_Command);
    UNREFERENCED_PARAMETER(_Mode);

    return 0;
}


void __cdecl clearerr(_Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_File);
}


int __cdecl setvbuf(_Inout_ FILE * _File,
                    _Inout_updates_opt_z_(_Size) char * _Buf,
                    _In_ int _Mode, _In_ size_t _Size)
{
    UNREFERENCED_PARAMETER(_File);
    UNREFERENCED_PARAMETER(_Buf);
    UNREFERENCED_PARAMETER(_Size);

    return 0;
}


FILE * __cdecl tmpfile(void)
{
    return 0;
}


int __cdecl remove(_In_z_ const char * _Filename)
{
    UNREFERENCED_PARAMETER(_Filename);

    return 0;
}


_Check_return_ _CRTIMP
int __cdecl rename(_In_z_ const char * _OldFilename, _In_z_ const char * _NewFilename)
{
    UNREFERENCED_PARAMETER(_OldFilename);
    UNREFERENCED_PARAMETER(_NewFilename);

    return 0;
}


int __cdecl ungetc(_In_ int _Ch, _Inout_ FILE * _File)
{
    UNREFERENCED_PARAMETER(_Ch);
    UNREFERENCED_PARAMETER(_File);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
