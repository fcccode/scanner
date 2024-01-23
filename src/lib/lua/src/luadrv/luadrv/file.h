#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


__declspec(noalias)
_Check_return_opt_
//_CRT_STDIO_INLINE 
int __CRTDECL fprintf(
    _Inout_                       FILE * const _Stream,
    _In_z_ _Printf_format_string_ char const * const _Format,
    ...);

void * __cdecl calloc(size_t number, size_t size);

int __CRTDECL vfprintf(
    _Inout_                       FILE * const _Stream,
    _In_z_ _Printf_format_string_ char const * const _Format,
    va_list           _ArgList
);

int __cdecl _open(_In_z_ const char * _Filename, _In_ int _OpenFlag, ...);
FILE * __cdecl fopen(_In_z_ const char * _Filename, _In_z_ const char * _Mode);
FILE * __cdecl freopen(_In_z_ const char * _Filename, _In_z_ const char * _Mode, _Inout_ FILE * _File);

int __cdecl feof(_In_ FILE * _File);

int __cdecl ferror(_In_ FILE * _File);

int __cdecl close(_In_ int _FileHandle);
int __cdecl fclose(_Inout_ FILE * _File);

size_t __cdecl fread(_Out_writes_bytes_(_ElementSize * _Count) void * _DstBuf,
                     _In_ size_t _ElementSize,
                     _In_ size_t _Count,
                     _Inout_ FILE * _File);

int __cdecl write(_In_ int _Filehandle, _In_reads_bytes_(_MaxCharCount) const void * _Buf, _In_ unsigned int _MaxCharCount);
size_t __cdecl fwrite(_In_reads_bytes_(_Size * _Count) const void * _Str,
                      _In_ size_t _Size,
                      _In_ size_t _Count,
                      _Inout_ FILE * _File);

int __cdecl getc(_Inout_ FILE * _File);

int __cdecl fseek(_Inout_ FILE * _File, _In_ long _Offset, _In_ int _Origin);

long __cdecl ftell(_Inout_ FILE * _File);

char * __cdecl fgets(_Out_writes_z_(_MaxCount) char * _Buf, _In_ int _MaxCount, _Inout_ FILE * _File);

int __cdecl _pclose(_Inout_ FILE * _File);

FILE * __cdecl _popen(_In_z_ const char * _Command, _In_z_ const char * _Mode);

void __cdecl clearerr(_Inout_ FILE * _File);

int __cdecl setvbuf(_Inout_ FILE * _File,
                    _Inout_updates_opt_z_(_Size) char * _Buf,
                    _In_ int _Mode,
                    _In_ size_t _Size);

FILE * __cdecl tmpfile(void);

int __cdecl remove(_In_z_ const char * _Filename);

_Check_return_ _CRTIMP
int __cdecl rename(_In_z_ const char * _OldFilename, _In_z_ const char * _NewFilename);

int __cdecl ungetc(_In_ int _Ch, _Inout_ FILE * _File);

FILE * __cdecl __acrt_iob_func(unsigned _X);


//////////////////////////////////////////////////////////////////////////////////////////////////
