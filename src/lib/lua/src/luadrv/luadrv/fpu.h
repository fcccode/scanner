#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


double  __cdecl frexp(_In_ double _X, _Out_ int * _Y);

float __CRTDECL ldexp(_In_ float _X, _In_ int _Y);

double  __cdecl floor(_In_ double _X);

double  __cdecl pow(_In_ double _X, _In_ double _Y);
double  __cdecl _CIpow(_In_ double _X, _In_ double _Y);

double  __cdecl fmod(_In_ double _X, _In_ double _Y);
double  __cdecl _CIfmod(_In_ double _X, _In_ double _Y);

double  __cdecl cosh(_In_ double _X);
double  __cdecl exp(_In_ double _X);
double  __cdecl _CIexp(_In_ double _X);
double  __cdecl log(_In_ double _X);
double  __cdecl _CIlog(_In_ double _X);
double  __cdecl log10(_In_ double _X);
double  __cdecl _CIlog10(_In_ double _X);
double  __cdecl sinh(_In_ double _X);
double  __cdecl tan(_In_ double _X);
double  __cdecl _CItan(_In_ double _X);
double  __cdecl tanh(_In_ double _X);

double  __cdecl acos(_In_ double _X);
double  __cdecl _CIacos(_In_ double _X);
double  __cdecl asin(_In_ double _X);
double  __cdecl _CIasin(_In_ double _X);
double  __cdecl atan(_In_ double _X);
double  __cdecl atan2(_In_ double _Y, _In_ double _X);
double  __cdecl _CIatan2(_In_ double _X);

double  __cdecl ceil(_In_ double _X);


//////////////////////////////////////////////////////////////////////////////////////////////////
