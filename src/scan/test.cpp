#include "test.h"
#include "udp.h"


int test()
{
    string source;
    GetActivityAdapter(source);

    //Syn4ScanTest(source.c_str(), "58.30.226.47", 3389);
    //Syn6ScanTest(source.c_str(), "fe80::95c9:6378:91c0:d5b2", 80);//2001:4860:4860::6464 53
    test_udp4(source.c_str());

    return ERROR_SUCCESS;
}
