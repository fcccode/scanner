#pragma once

#include "pch.h"

extern "C" {//����취���磺x64���ڰ���Ŀ¼���.\lib\VCWIN64A\include����.\lib\VCWIN64A\include
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/x509err.h>
#include <openssl/x509v3err.h>
#include <openssl/pem.h> 
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
}


#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")


int WINAPI tls_client(int argc, char ** argv);