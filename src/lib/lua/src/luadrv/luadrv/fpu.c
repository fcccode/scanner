#include "fpu.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


double  __cdecl frexp(_In_ double _X, _Out_ int * _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);
    return 0;
}


float __CRTDECL ldexp(_In_ float _X, _In_ int _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);
    return 0;

    //return (ldexpf(_X, _Y));
}


#pragma function(pow)
double  __cdecl pow(_In_ double _X, _In_ double _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);

    return 0;
}


#pragma function(_CIpow)
double  __cdecl _CIpow(_In_ double _X, _In_ double _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);

    return 0;
}


#pragma function(fmod)
double  __cdecl fmod(_In_ double _X, _In_ double _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);

    return 0;
}


#pragma function(_CIfmod)
double  __cdecl _CIfmod(_In_ double _X, _In_ double _Y)
{
    UNREFERENCED_PARAMETER(_X);
    UNREFERENCED_PARAMETER(_Y);

    return 0;
}


#undef exit
#pragma function(exit)
__declspec(noreturn) void __cdecl exit(_In_ int _Code)
{
    UNREFERENCED_PARAMETER(_Code);

    return 0;
}


#pragma function(cosh)
double  __cdecl cosh(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(exp)
double  __cdecl exp(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIexp)
double  __cdecl _CIexp(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(log)
double  __cdecl log(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIlog)
double  __cdecl _CIlog(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(log10)
double  __cdecl log10(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIlog10)
double  __cdecl _CIlog10(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(sinh)
double  __cdecl sinh(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(tan)
double  __cdecl tan(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CItan)
double  __cdecl _CItan(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(tanh)
double  __cdecl tanh(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(acos)
double  __cdecl acos(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIacos)
double  __cdecl _CIacos(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(asin)
double  __cdecl asin(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIasin)
double  __cdecl _CIasin(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(atan)
double  __cdecl atan(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(atan2)
double  __cdecl atan2(_In_ double _Y, _In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(_CIatan2)
double  __cdecl _CIatan2(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(ceil)
double  __cdecl ceil(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);

    return 0;
}


#pragma function(floor)
double  __cdecl floor(_In_ double _X)
{
    UNREFERENCED_PARAMETER(_X);
    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
